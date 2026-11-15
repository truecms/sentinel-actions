'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  hasRecentHandshake,
  formatTimeoutSeconds,
  readInputs,
  resolveIPv4,
  routeUsesInterface,
  runMain,
  runPost,
} = require('../wireguard-ssh');

function baseEnv(tempDir) {
  return {
    INPUT_CONFIG: '[Interface]\nPrivateKey = secret\nAddress = 10.50.0.2/32\n[Peer]\nPublicKey = peer\nEndpoint = vpn.example:51820\nAllowedIPs = 192.0.2.4/32',
    'INPUT_TARGET-HOST': '192.0.2.4',
    'INPUT_TARGET-PORT': '63022',
    'INPUT_TIMEOUT-SECONDS': '30',
    GITHUB_STATE: path.join(tempDir, 'state'),
    RUNNER_TEMP: tempDir,
  };
}

test('reads and validates action inputs', () => {
  const inputs = readInputs(baseEnv('/tmp'));
  assert.equal(inputs.targetHost, '192.0.2.4');
  assert.equal(inputs.targetPort, 63022);
  assert.equal(inputs.timeoutSeconds, 30);
});

test('resolves IPv4 through a bounded getent subprocess', () => {
  let call;
  const addresses = resolveIPv4('deploy.example', (command, args, options) => {
    call = { command, args, options };
    return '192.0.2.4 STREAM deploy.example\n192.0.2.4 DGRAM deploy.example\n198.51.100.9 STREAM deploy.example\n';
  }, 725);

  assert.deepEqual(addresses, ['192.0.2.4', '198.51.100.9']);
  assert.deepEqual(call, {
    command: 'getent',
    args: ['ahostsv4', 'deploy.example'],
    options: { timeout: 725, killSignal: 'SIGKILL' },
  });
  assert.equal(formatTimeoutSeconds(30000), '30s');
  assert.equal(formatTimeoutSeconds(1250), '1.25s');
});

test('rejects a missing secret, invalid port, and excessive timeout', () => {
  assert.throws(() => readInputs({}), /Missing required input: config/);
  assert.throws(() => readInputs({ ...baseEnv('/tmp'), 'INPUT_TARGET-PORT': '0' }), /target-port/);
  assert.throws(() => readInputs({ ...baseEnv('/tmp'), 'INPUT_TIMEOUT-SECONDS': '301' }), /timeout-seconds/);
  assert.throws(() => readInputs({
    ...baseEnv('/tmp'),
    INPUT_CONFIG: `${baseEnv('/tmp').INPUT_CONFIG}\nPostUp = touch /tmp/untrusted`,
  }), /must not contain/);
});

test('requires the route to use the exact WireGuard interface', () => {
  assert.equal(routeUsesInterface('192.0.2.4 dev scwg-a1b2c3d4 src 10.50.0.2', 'scwg-a1b2c3d4'), true);
  assert.equal(routeUsesInterface('192.0.2.4 dev eth0 src 198.51.100.8', 'scwg-a1b2c3d4'), false);
  assert.equal(routeUsesInterface('192.0.2.4 dev scwg-a1b2c3d40', 'scwg-a1b2c3d4'), false);
});

test('requires a handshake newer than this connection attempt', () => {
  assert.equal(hasRecentHandshake('peer-key\t1800000000\n', 1799999999), true);
  assert.equal(hasRecentHandshake('peer-key\t1800000000\n', 1800000001), false);
  assert.equal(hasRecentHandshake('peer-key\t0\n', 0), false);
});

test('post cleanup with no saved state does not try to connect', () => {
  let called = false;
  runPost({}, { run: () => { called = true; } });
  assert.equal(called, false);
});

test('brings up a private config, verifies the routed SSH target, and saves post state', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wireguard-action-test-'));
  const env = baseEnv(tempDir);
  const calls = [];
  let setupOptions;
  const nowMs = Date.now();
  const nowSeconds = Math.floor(nowMs / 1000);
  const run = (command, args, options = {}) => {
    calls.push([command, args]);
    if (command === 'sudo' && args.includes('wg-quick') && args.includes('up')) setupOptions = { args, options };
    if (command === 'ip' && args[0] === '-4') return '192.0.2.4 dev scwg-a1b2c3d4 src 10.50.0.2';
    if (command === 'sudo' && args[0] === 'wg' && args[1] === 'show') return `peer-key\t${nowSeconds}\n`;
    return '';
  };

  await runMain(env, {
    platform: 'linux',
    randomHex: () => 'a1b2c3d4',
    resolveIPv4: () => ['192.0.2.4'],
    probeTcp: async () => true,
    now: () => nowMs,
    run,
    sleep: async () => {},
  });

  const configPath = path.join(tempDir, 'scwg-a1b2c3d4.conf');
  assert.equal(fs.readFileSync(configPath, 'utf8'), `${env.INPUT_CONFIG}\n`);
  assert.equal(fs.statSync(configPath).mode & 0o777, 0o600);
  assert.match(fs.readFileSync(env.GITHUB_STATE, 'utf8'), /INTERFACE=scwg-a1b2c3d4/);
  assert.match(fs.readFileSync(env.GITHUB_STATE, 'utf8'), /CONFIG_PATH=.*scwg-a1b2c3d4\.conf/);
  assert.ok(calls.some(([command, args]) => command === 'sudo' && args.includes('wg-quick') && args.includes('up')));
  assert.ok(calls.some(([command, args]) => command === 'ip' && args[0] === '-4' && args[3] === '192.0.2.4'));
  assert.equal(setupOptions.options.timeout, 31000);
  assert.equal(setupOptions.options.stdio, undefined);
  assert.deepEqual(setupOptions.args.slice(0, 4), ['timeout', '--signal=KILL', '30s', 'wg-quick']);

  runPost({
    ...env,
    STATE_INTERFACE: 'scwg-a1b2c3d4',
    STATE_CONFIG_PATH: configPath,
  }, {
    run: (command, args) => {
      if (command === 'ip' && args[0] === 'link') return '3: scwg-a1b2c3d4: <POINTOPOINT,NOARP,UP>';
      calls.push([command, args]);
      return '';
    },
  });

  assert.equal(fs.existsSync(configPath), false);
  assert.ok(calls.some(([command, args]) => command === 'sudo' && args.includes('wg-quick') && args.includes('down')));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('fails closed when the target route bypasses the tunnel', async () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wireguard-action-test-'));
  const env = baseEnv(tempDir);
  await assert.rejects(runMain(env, {
    platform: 'linux',
    randomHex: () => 'a1b2c3d4',
    resolveIPv4: () => ['192.0.2.4'],
    run: (command, args) => command === 'ip' && args[0] === '-4'
      ? '192.0.2.4 dev eth0 src 198.51.100.8'
      : '',
  }), /not routed through WireGuard/);
  fs.rmSync(tempDir, { recursive: true, force: true });
});
