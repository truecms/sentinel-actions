# WireGuard SSH access for GitHub Actions

Connect an Ubuntu runner to a WireGuard peer before deploying to a server whose
SSH firewall rule allows only the VPN gateway or peer network. The action checks
that every IPv4 address for the SSH host routes through the tunnel, confirms the
SSH port is reachable, and removes the tunnel and temporary client file after
the job, including when later steps fail.

For a full walk-through, see the guide
[Keep SSH private for GitHub Actions deployments with WireGuard](https://sentinelconnector.io/guides/github-actions-wireguard-ssh).

The runner needs passwordless `sudo`. Use a Linux runner directly; a job
container cannot configure the runner host's network routes. The action installs
`wireguard-tools` and `iproute2` with apt when they are missing. If the peer
configuration contains a `DNS` entry, it also installs `openresolv` when needed.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `config` | Yes | — | Complete WireGuard client configuration. Pass it from an Actions secret. |
| `target-host` | Yes | — | SSH destination IPv4 address or hostname. |
| `target-port` | No | `22` | SSH port. |
| `timeout-seconds` | No | `30` | Maximum time for tunnel setup, target DNS resolution and SSH reachability after required tools are installed; from 1 to 300. |

The peer's `AllowedIPs` must include every IPv4 address resolved for
`target-host`. This action deliberately fails if the operating system would
route any resolved IPv4 address outside the tunnel. Use `ssh -4` for subsequent
connections to the target so OpenSSH cannot select an unchecked IPv6 address.
The action resolves hostnames through the runner's system host database with a
bounded `getent ahostsv4` subprocess. Use a split tunnel for the SSH
destination; this check does not support full-tunnel routes.

## Configure the server and workflow

1. Create a dedicated WireGuard peer for the deployment workflow. Use a unique
   key and VPN address for each concurrently running workflow.
2. Put the complete client configuration in a repository or environment secret
   such as `WIREGUARD_CONFIG_DEPLOY`. Do not commit it or print it in workflow
   logs. Restrict access to deployment secrets and require environment approval
   where that fits your release process. Only use a configuration controlled by
   trusted deployment administrators. The action rejects `PreUp`, `PostUp`,
   `PreDown`, `PostDown` and `SaveConfig` directives because `wg-quick` runs as
   root and those directives can execute commands.
3. Configure the server firewall to allow the SSH port from the VPN gateway's
   egress address when the gateway forwards/NATs traffic, or from the client's
   VPN address when the server routes the peer network directly. Deny public SSH
   access after the VPN path has been tested. Keep an independent, restricted
   administrator path for recovery.
4. Keep SSH key authentication and host-key checking enabled. VPN connectivity
   controls network reachability; it does not replace SSH authentication. Use
   IPv4 (`ssh -4`) for commands to the target, matching the action's route check.
5. Use a reviewed release tag or full commit SHA in `uses`. The example pins
   the inspected action commit; review it before adoption and update it deliberately.

## Example workflow

See [the complete deploy workflow](examples/deploy.yml). It is manually
triggered on `main`, uses a `production` environment and repository-scoped
concurrency, then invokes a server-side command with a separate SSH key and
verified host key. Create and protect the environment first; a name in the
workflow does not configure deployment restrictions. Replace the example command
with your own reviewed deployment procedure. Test the complete path, firewall
restrictions, cleanup and recovery on a non-production target before use.
Concurrent deployments in different repositories need separate peers or
external coordination. A pending workflow can be replaced under GitHub's
default concurrency rules.

## Troubleshooting

- **The SSH host is not routed through WireGuard:** add its IPv4 address or
  subnet to the peer's `AllowedIPs`, then check the gateway's forwarding and
  server firewall rules.
- **The port does not become reachable:** confirm the peer endpoint's UDP port
  is reachable from the runner, the server allows SSH from the VPN path, and
  `target-host` and `target-port` identify the intended SSH service.
- **DNS does not resolve:** use an IP address or configure a DNS resolver in the
  WireGuard peer configuration. The action installs `openresolv` for `wg-quick`
  DNS settings.
- **Cleanup fails:** the action reports the failed interface cleanup and still
  removes the temporary client configuration. GitHub-hosted runners are
  ephemeral; investigate the runner logs before retrying a self-hosted runner.
