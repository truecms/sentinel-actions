'use strict';

const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const INTERFACE_PREFIX = 'scwg-';
const MAX_TIMEOUT_SECONDS = 300;

function getInput(env, name, required = false, fallback = '') {
  const value = env[`INPUT_${name.toUpperCase()}`] || fallback;
  if (required && !value.trim()) {
    throw new Error(`Missing required input: ${name}.`);
  }
  return value.trim();
}

function readInputs(env) {
  const config = getInput(env, 'config', true);
  if (config.includes('\0')) {
    throw new Error('The WireGuard configuration contains a null byte.');
  }
  if (/^\s*(?:PreUp|PostUp|PreDown|PostDown|SaveConfig)\s*=/im.test(config)) {
    throw new Error('The WireGuard configuration must not contain PreUp, PostUp, PreDown, PostDown or SaveConfig directives.');
  }

  const targetHost = getInput(env, 'target-host', true);
  if (targetHost.length > 253 || /[\s\0]/.test(targetHost)) {
    throw new Error('Input target-host must be an IPv4 address or hostname without whitespace.');
  }
  const targetPortText = getInput(env, 'target-port', false, '22');
  const timeoutText = getInput(env, 'timeout-seconds', false, '30');
  const targetPort = Number(targetPortText);
  const timeoutSeconds = Number(timeoutText);

  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    throw new Error('Input target-port must be an integer from 1 to 65535.');
  }
  if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > MAX_TIMEOUT_SECONDS) {
    throw new Error(`Input timeout-seconds must be an integer from 1 to ${MAX_TIMEOUT_SECONDS}.`);
  }

  return { config, targetHost, targetPort, timeoutSeconds };
}

function routeUsesInterface(route, iface) {
  const tokens = route.trim().split(/\s+/);
  const deviceIndex = tokens.indexOf('dev');
  return deviceIndex >= 0 && tokens[deviceIndex + 1] === iface;
}

function hasRecentHandshake(output, earliestTimestampSeconds) {
  return output.split(/\r?\n/).some((line) => {
    const fields = line.trim().split(/\s+/);
    const timestamp = Number(fields[1]);
    return fields.length >= 2 && Number.isFinite(timestamp) && timestamp > 0 && timestamp >= earliestTimestampSeconds;
  });
}

function defaultRun(command, args, options = {}) {
  return execFileSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
}

function ensureWireGuardTools(run, config) {
  const needsOpenresolv = /(?:^|\n)\s*DNS\s*=/i.test(config);
  try {
    run('sh', ['-c', 'command -v wg-quick >/dev/null 2>&1']);
    run('sh', ['-c', 'command -v wg >/dev/null 2>&1']);
    run('sh', ['-c', 'command -v ip >/dev/null 2>&1']);
    if (needsOpenresolv) run('sh', ['-c', 'command -v resolvconf >/dev/null 2>&1']);
    return;
  }
  catch (_error) {
    // GitHub-hosted Ubuntu runners have passwordless sudo. Installation is
    // skipped when the runner already has the WireGuard and routing tools.
  }

  run('sudo', ['apt-get', 'update', '-q'], { stdio: 'inherit' });
  run('sudo', [
    'apt-get', 'install', '-y', '-q', '--no-install-recommends',
    'wireguard-tools', 'iproute2', 'openresolv',
  ], { stdio: 'inherit' });
  run('sh', ['-c', 'command -v wg-quick >/dev/null 2>&1']);
  run('sh', ['-c', 'command -v wg >/dev/null 2>&1']);
  run('sh', ['-c', 'command -v ip >/dev/null 2>&1']);
  if (needsOpenresolv) run('sh', ['-c', 'command -v resolvconf >/dev/null 2>&1']);
}

function saveState(env, iface, configPath) {
  if (!env.GITHUB_STATE) {
    throw new Error('GITHUB_STATE is missing; this action must run inside GitHub Actions.');
  }
  fs.appendFileSync(env.GITHUB_STATE, `INTERFACE=${iface}\nCONFIG_PATH=${configPath}\n`, { mode: 0o600 });
}

function formatTimeoutSeconds(timeoutMs) {
  const seconds = Math.max(0.001, timeoutMs / 1000);
  return `${seconds.toFixed(3).replace(/\.?0+$/, '')}s`;
}

function resolveIPv4(host, run, timeoutMs) {
  if (timeoutMs <= 0) {
    throw new Error(`Resolving the SSH destination ${host} exceeded the configured timeout.`);
  }

  let output;
  try {
    // A bounded subprocess can be killed on timeout. dns.lookup() uses
    // getaddrinfo requests that cannot be cancelled and can keep Node alive.
    output = run('getent', ['ahostsv4', host], {
      timeout: Math.max(1, Math.ceil(timeoutMs)),
      killSignal: 'SIGKILL',
    });
  }
  catch (_error) {
    throw new Error(`Could not resolve the SSH destination ${host} to IPv4 within the configured timeout.`);
  }

  const addresses = [...new Set(String(output)
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/)[0])
    .filter((address) => net.isIPv4(address)))];
  if (!addresses.length) {
    throw new Error(`The SSH destination ${host} did not resolve to an IPv4 address.`);
  }
  return addresses;
}

function probeTcp(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port, family: 4 });
    let settled = false;
    const finish = (reachable) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(reachable);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runMain(env = process.env, deps = {}) {
  const platform = deps.platform || process.platform;
  if (platform !== 'linux') {
    throw new Error('This action requires a Linux runner. Use an Ubuntu GitHub-hosted runner without a job container.');
  }

  const { config, targetHost, targetPort, timeoutSeconds } = readInputs(env);
  const runnerTemp = env.RUNNER_TEMP;
  if (!runnerTemp) {
    throw new Error('RUNNER_TEMP is missing; this action must run inside GitHub Actions.');
  }

  const run = deps.run || defaultRun;
  const lookupIPv4 = deps.resolveIPv4 || resolveIPv4;
  const tcpProbe = deps.probeTcp || probeTcp;
  const wait = deps.sleep || sleep;
  const now = deps.now || Date.now;
  const randomHex = deps.randomHex || (() => crypto.randomBytes(4).toString('hex'));
  const iface = `${INTERFACE_PREFIX}${randomHex()}`;
  const configPath = path.join(runnerTemp, `${iface}.conf`);

  ensureWireGuardTools(run, config);
  fs.mkdirSync(runnerTemp, { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, `${config.trimEnd()}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  try {
    saveState(env, iface, configPath);
  }
  catch (error) {
    fs.unlinkSync(configPath);
    throw error;
  }

  const startedAt = now();
  const deadline = startedAt + timeoutSeconds * 1000;
  try {
    const setupTimeoutMs = deadline - now();
    if (setupTimeoutMs <= 0) {
      throw new Error('WireGuard setup exceeded the configured timeout.');
    }
    run('sudo', [
      'timeout', '--signal=KILL', formatTimeoutSeconds(setupTimeoutMs),
      'wg-quick', 'up', configPath,
    ], { timeout: Math.ceil(setupTimeoutMs) + 1000, killSignal: 'SIGKILL' });
  }
  catch (_error) {
    throw new Error('WireGuard setup failed or timed out. Check the trusted peer configuration, runner privileges, endpoint DNS and UDP access. Subprocess output is suppressed to protect the configuration secret.');
  }
  console.log(`WireGuard interface ${iface} is up.`);

  const addresses = lookupIPv4(targetHost, run, deadline - now());
  for (const address of addresses) {
    const routeTimeoutMs = deadline - now();
    if (routeTimeoutMs <= 0) {
      throw new Error('Checking the SSH destination route exceeded the configured timeout.');
    }
    const route = run('ip', ['-4', 'route', 'get', address], {
      timeout: Math.max(1, Math.ceil(routeTimeoutMs)),
      killSignal: 'SIGKILL',
    });
    if (!routeUsesInterface(String(route), iface)) {
      throw new Error(`The SSH destination ${targetHost} is not routed through WireGuard. Include its IPv4 address in the peer AllowedIPs.`);
    }
  }

  const earliestHandshake = Math.floor(startedAt / 1000) - 1;
  while (now() < deadline) {
    for (const address of addresses) {
      const remaining = deadline - now();
      if (remaining <= 0) break;
      if (await tcpProbe(address, targetPort, Math.min(5000, remaining))) {
        const handshakes = run('sudo', ['wg', 'show', iface, 'latest-handshakes'], {
          timeout: Math.max(1, Math.min(2000, deadline - now())),
        });
        if (hasRecentHandshake(String(handshakes), earliestHandshake)) {
          console.log(`SSH destination ${targetHost}:${targetPort} is reachable through WireGuard.`);
          return;
        }
      }
    }
    await wait(Math.min(1000, Math.max(0, deadline - now())));
  }

  throw new Error(`The SSH destination ${targetHost}:${targetPort} did not become reachable through WireGuard within ${timeoutSeconds} seconds.`);
}

function runPost(env = process.env, deps = {}) {
  const iface = env.STATE_INTERFACE;
  const configPath = env.STATE_CONFIG_PATH;
  if (!iface && !configPath) return;

  const runnerTemp = env.RUNNER_TEMP;
  if (!runnerTemp || !/^scwg-[0-9a-f]{8}$/.test(iface || '')) {
    throw new Error('Saved WireGuard cleanup state is invalid.');
  }
  const expectedConfigPath = path.join(path.resolve(runnerTemp), `${iface}.conf`);
  if (path.resolve(configPath || '') !== expectedConfigPath) {
    throw new Error('Saved WireGuard configuration path is invalid.');
  }

  const run = deps.run || defaultRun;
  let interfaceExists = false;
  try {
    run('ip', ['link', 'show', 'dev', iface]);
    interfaceExists = true;
  }
  catch (_error) {
    // A failed setup may have saved state before creating the interface.
  }

  let cleanupError;
  try {
    if (interfaceExists) {
      run('sudo', [
        'timeout', '--signal=TERM', '--kill-after=5s', '25s',
        'wg-quick', 'down', configPath,
      ], { timeout: 30000 });
      console.log(`WireGuard interface ${iface} is down.`);
    }
  }
  catch (_error) {
    cleanupError = new Error(`Could not shut down WireGuard interface ${iface}. Subprocess output is suppressed to protect the configuration secret.`);
  }
  finally {
    try {
      fs.unlinkSync(configPath);
    }
    catch (error) {
      if (error.code !== 'ENOENT') {
        cleanupError ||= new Error('Could not remove the temporary WireGuard configuration file.');
      }
    }
  }

  if (cleanupError) throw cleanupError;
}

async function main() {
  try {
    await runMain();
  }
  catch (error) {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  formatTimeoutSeconds,
  hasRecentHandshake,
  readInputs,
  resolveIPv4,
  routeUsesInterface,
  runMain,
  runPost,
};
