# Sandbox

Run [Pi](https://pi.dev) or [omp](https://omp.sh) inside an ephemeral smolvm microVM, with a writable project directory, persistent native session history, and private copies of the host's agent configuration.

## Prerequisites

- **smolvm** with privileged init, `--net-backend virtio-net`, `--no-init-cache`, and `--secret-env` support. Install with:
  ```bash
  curl -sSL https://smolmachines.com/install.sh | bash
  ```
- **Docker with buildx** and a running daemon, such as Docker Desktop or OrbStack.
- **realpath** on the host, used to check mount paths before starting Docker or the VM.

## Quick Start

Build and run the current working tree locally, without publishing:

```bash
docker buildx build --load -f Dockerfile -t sandbox:local .
SANDBOX_IMAGE=sandbox:local ./sandbox.sh /path/to/project
```

The VM opens an interactive login shell. Its zsh prompt starts with `🔒 ` to identify the sandbox; the rest of the prompt is unchanged. Run `pi` or `omp` from that shell.

To use the published image instead:

```bash
./sandbox.sh /path/to/project
```

Without `SANDBOX_IMAGE`, the launcher pulls `jasonbaker/sandbox:latest`. A local image override skips that pull. Images must advertise the current configuration and network-policy layout. If the published image is older, the launcher builds a matching `sandbox:config-local` image from the sources beside the launcher, without publishing it. An incompatible explicit override fails with a rebuild instruction. Rebuild after changing the Dockerfile, Python entrypoints, or either sandbox JSON profile.

## Usage

```bash
./sandbox.sh
./sandbox.sh /path/to/project
./sandbox.sh --agent omp /path/to/project
./sandbox.sh --ssh-agent /path/to/project
./sandbox.sh --dns 100.100.100.100 /path/to/project
./sandbox.sh --help
```

The launcher passes `--dns 100.100.100.100` to smolvm, the Tailscale resolver address, unless you pass `--dns` yourself. See [Tailnet DNS](#tailnet-dns) for why that address is the right default.

`--agent` and `AGENT` select the startup hint, not an automatically launched process. Both agents remain available in the same shell. `--agent` overrides `AGENT`; accepted values are `pi` and `omp`.

The workspace must be an existing directory. The launcher resolves symlinks and rejects your home directory, its ancestors, and paths that overlap either agent configuration directory. This prevents the writable workspace from exposing the same configuration that is mounted read-only. Paths containing colons or newlines are rejected because they cannot be passed safely through smolvm's volume syntax.

The workload retains only filesystem capabilities needed to edit host-owned workspace files. Network-administration, raw-socket, namespace-administration, and privilege-escalation capabilities are removed before the shell or agent starts. Privileged nested-sandbox mode is no longer available because it would let the workload bypass the network policy; extensions that require privileged namespace creation are not supported.

### Installing Globally

Symlink the launcher into a directory on your `PATH`:

```bash
ln -s /path/to/sandbox.sh /usr/local/bin/sandbox
sandbox /path/to/project
```

## Reusing and Reclaiming VMs

`sandbox-vm.py` reuses a VM that is already serving a project, and reclaims
VMs that an interrupted run left behind.

Start a sandbox for a directory and it picks up whatever exists there:

```bash
./sandbox-vm.py reuse --target ~/src/api
```

There are two outcomes.

- A VM for that directory is running with a live launcher: the command execs a
  login shell inside that VM. The terminal joins the existing VM beside its
  console session, and nothing new starts.
- A VM for that directory is running with a dead launcher, or none is running:
  `sandbox.sh` starts for that directory, including the first run ever.

To join a running VM without the create path, or to reach it by name:

```bash
./sandbox-vm.py attach --target ~/src/api      # login shell in its VM
./sandbox-vm.py attach --vm vm-1a2b3c4d        # same, addressed by name
./sandbox-vm.py attach -- vm -c 'hostname'     # run a command instead of a shell
```

The shell starts in the VM's workload namespace, where the project mount, the
egress policy, and the seeded configuration are in force. The first terminal's
console session keeps running; a second `sandbox.sh` for the same directory
would instead start a second VM, because `machine run` connects its console to
the VM's single serial port.

Sessions and history survive every case. They live in host directories mounted
into each VM, so a new VM sees the work of the previous one.

A running VM is reused, never restarted in place. smolvm skips init commands
when it restarts a stopped machine, and init is what installs the pinned
tailnet policy, so a restarted machine would run an agent under a stale policy.
`reuse` starts a fresh VM instead, a 4 to 5 second boot when the image archive
is already cached.

A run that exits on its own already reaps its own VM. A run that is killed, or
whose terminal closes, leaks the VM: it stays in `smolvm machine ls` as
`running (eph)`, holding its memory. Reclaim those VMs with:

```bash
./sandbox-vm.py list            # show VMs and who owns them
./sandbox-vm.py reap --dry-run  # report what would stop
./sandbox-vm.py reap            # stop abandoned VMs, free memory
```

`reap` judges each VM by process ownership. A live launcher is an ancestor of
its VM's boot process, so an attached VM is kept. A leaked VM's boot process
has been reparented to launchd, so `reap` stops it. Only VMs running the
sandbox image are considered; other smolvm machines are untouched. `list`
reports the same result as `attached` or `detached`.

`reap --include-named` includes detached named machines (created with
`machine run --name`), which are left alone by default. `reap --all` does the
same and also deletes stopped machines, freeing their disk.
`stop NAME --delete` deletes one machine.

## Sharing Agent Configuration

The host sources and VM-local copies are separate:

| Agent | Read-only host source in VM | Writable VM-local configuration |
|---|---|---|
| Pi | `/root/.pi-host` from host `~/.pi` | `$HOME/.pi`, including `$HOME/.pi/agent` |
| omp | `/root/.omp-host` from host `~/.omp` | `$HOME/.omp`, including `$HOME/.omp/agent` |

At startup, `vm-seed.py` snapshots each source into its own private directory. Root-level configuration, agent settings, credentials, extensions, and named profiles retain their directory structure. There is no global `PI_CODING_AGENT_DIR` override to mix the agents' settings or credentials.

Seeding runs before the shell starts and only once per VM. Nested shells do not refresh the snapshot or overwrite changes made by an agent. Host configuration changes take effect in the next VM, not in an existing VM's private copy. VM-local settings and refreshed tokens are discarded when the VM exits. The mounted source directories remain live and readable.

### Persistent Sessions

The following host directories are mounted writable at their native paths inside the VM:

| Agent | Shared host state |
|---|---|
| Pi | `~/.pi/agent/sessions` |
| omp default profile | `~/.omp/agent/sessions` and `~/.omp/agent/blobs` |
| Each existing omp profile | `~/.omp/profiles/NAME/agent/sessions` and `~/.omp/profiles/NAME/agent/blobs` |

The full session trees are shared, including omp's same-basename subdirectories for artifacts and subagent transcripts. Its content-addressed image blobs are also shared. The launcher creates missing state directories and rejects symlinked state paths; existing state-directory contents and permissions are not changed by seeding.

The guest uses the host's canonical `HOME`, project working directory, and `TMPDIR` paths. This keeps both agents' project-history buckets and recorded working directories consistent between host and VM. It does **not** mount the full host home or temporary directory: all other paths remain VM-private.

The guest's `~/.local/bin` refers to the image-installed tools, not the host's executable directory. Its login shell can load the image's tool environment without exposing host binaries.

Open the same project on the host or in a later VM and use the agent's normal history controls, such as `pi --continue`, `omp --continue`, or `omp --resume SESSION_ID`. No custom session directory or import step is required. Session files are written directly to the host mounts, not copied back during shutdown. Only data the agent has actually written is preserved; this is not a guarantee against buffered writes or a torn final record.

Create named omp profiles on the host before starting the VM. A profile created only inside an already running VM has no shared state mounts and is discarded with that VM.

**Do not edit the same session from multiple host/VM processes at once.** Session ownership does not coordinate across separate VMs or between macOS and Linux. Shared history is writable host state: VM code can alter or delete existing transcripts, artifacts, and blobs.

SQLite history indexes, terminal breadcrumbs, and runtime leases remain private to each process environment. Native JSONL history remains discoverable without sharing a live SQLite database. Sessions left in older VMs are not automatically imported, and legacy `/workspace` working directories are not rewritten.

### Snapshot Rules

- Copied directories are private (`0700`). Ordinary copied files are `0600`; files with the owner's executable bit keep that bit as `0700`. These rules do not change the shared state mounts.
- Symlinks, sockets, devices, and FIFOs are not copied or followed. Symlinked extensions must be installed as ordinary files inside the VM if needed.
- Directories named `sessions`, `terminal-sessions`, `cache`, `caches`, `logs`, `bin`, `__pycache__`, or `.git` are omitted at any depth. Host binaries and cached native dependencies may not run on Linux; install required Linux dependencies in the VM.
- At each configuration root (including named profile roots), `run`, `ssh-control`, `puppeteer`, `natives`, and `.supervisor` are omitted. These contain host daemon state, browser profiles, sockets, or platform-specific binaries. A portable extension directory such as `agent/extensions/run` is still copied.
- `history.db*`, `trust.db*`, `trust.json`, `.seeded`, and SQLite journal sidecars are omitted. Host trust decisions are not imported from those files.
- SQLite `.db` files use a read-only SQLite backup, including committed WAL data, rather than a raw copy of a live database. An unreadable or invalid configuration database stops boot with its path and SQLite error instead of silently dropping credentials or printing file contents. A live WAL database must have readable WAL/SHM files; if SQLite cannot read it through the read-only mount, stop its host writer or checkpoint it before launching again.
- Pi receives `sandbox.json.autonomous` as its VM-local `agent/sandbox.json`. This is a Pi extension policy, not an omp policy or an OS-level security boundary.

Omitting files from the private snapshot does **not** hide them from code inside the VM: the full host source directories are still mounted read-only. Do not share a directory whose contents the agent must not read.

## LLM Backends

### Cloud Mode

When `LLM_BASE_URL` is unset or empty, nonempty `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` environment variables are forwarded using smolvm's `--secret-env`. Their values do not appear in launcher command arguments or smolvm's persisted machine record.

```bash
export ANTHROPIC_API_KEY="..."
./sandbox.sh /path/to/project
```

The agents can also use credentials from their copied configuration.

### Custom Model Endpoint

```bash
export LLM_BASE_URL="https://spark1.taild8834b.ts.net"
./sandbox.sh /path/to/project
```

The endpoint is passed unchanged as `OPENAI_BASE_URL` and `LLM_BASE_URL` through `--secret-env`, without printing it. When it is set, the two forwarded cloud API key variables are omitted; credentials already in shared configuration are not removed.

There is no automatic host-loopback or LAN rewriting. `localhost` means the VM itself. The network policy blocks host LAN endpoints and other private services; use the permitted Spark1 HTTPS endpoint or a public endpoint.

### Tailnet DNS

`sandbox-network.json` names a MagicDNS host, so the guest needs a resolver that knows tailnet names. smolvm's resolver forwards to public nameservers by default, and those do not, which is why the launcher sets `--dns 100.100.100.100` when you don't. That address is Tailscale's resolver, defined in [tailscale/hostenv](https://pkg.go.dev/tailscale.com/tsd/tailnetsock) as `100.100.100.100`; it answers tailnet names and forwards everything else to public nameservers, so it behaves like the public default wherever Tailscale is absent. Passing `--dns` replaces it:

```bash
./sandbox.sh --dns 1.1.1.1 /path/to/project
```

Note this requires the host's Tailscale connection and DNS service to be available. It fixes resolver selection; it does not enroll the VM as a separate Tailscale node or give it an independent access policy. Tailnet connections through the host can still use the host's permissions. If startup reports `resolving tailnet host ... failed`, the host is not resolving MagicDNS names: check `tailscale status` and `dscacheutil -q host -a name spark1.taild8834b.ts.net` there.

## Network Policy

`sandbox-network.json` selects `spark1.taild8834b.ts.net` on TCP port `443`. At each VM boot, trusted init resolves it, verifies that all returned addresses are Tailscale addresses, and atomically installs an nftables policy before agent configuration is seeded or any workload starts. Startup fails if resolution or policy installation fails. Addresses are pinned for that VM's lifetime; restart it after a peer address changes.

| Destination | Workload access |
|---|---|
| Public Internet | Allowed |
| Spark1's pinned Tailscale addresses | TCP 443 only |
| Other tailnet, LAN, link-local, or reserved addresses | Blocked |
| Configured DNS resolver addresses | TCP/UDP 53 only |
| VM loopback | Allowed for VM-local services |

The rule constrains destination IPs and TCP ports, not HTTP paths or the contents of HTTPS requests. Public Internet access still permits external proxies and data upload.

`sandbox.smolfile` runs trusted network init with VM-grade privileges. The launcher forces `virtio-net` so packets pass through the guest kernel and uses `--no-init-cache` so every VM gets fresh rules and resolver addresses. The seeder then uses `setpriv` to retain only `CAP_DAC_OVERRIDE` and `CAP_FOWNER`, with no ambient/inheritable capabilities and `no_new_privs`. The workload cannot modify nftables, create raw packet sockets, or regrant network privileges. These rules are inside the VM; no host firewall or tailnet ACL is changed.

## Security Boundaries

- The microVM is the host isolation boundary. The project and the session/blob directories listed above are mounted writable. Host configuration files remain available through read-only source mounts and VM-private snapshots.
- Trusted init configures the network before the workload runs. The workload remains root inside the guest with filesystem-only capabilities; read-only host mounts are also enforced by the backing filesystem. Private file modes do not hide credentials from the agent itself.
- SSH forwarding is **off by default**. `--ssh-agent` requires an existing `SSH_AUTH_SOCK` Unix socket. Forwarding does not copy private keys, but it allows VM processes to request signatures and authenticate as you. Prefer a dedicated agent with only the keys needed for this project.
- Credentials in shared configuration are readable inside the VM. An agent, extension, or compromised dependency can disclose them over the network. Read-only configuration mounts prevent changes to those files; they do not prevent credential theft or use.
- The workspace is writable host state, including its `.git` directory and any secrets already in the workspace. Review changes before running host-side scripts or hooks.
- Public Internet access remains enabled; private/tailnet access is restricted by the network policy above. The host must remain connected to Tailscale. The VM is not enrolled as a separate Tailscale node.
- Agent extensions and configuration are executable/trusted inputs, not sanitized data. The Pi extension's filesystem rules are defense in depth, not a replacement for the microVM and read-only mounts.
- Trust the image source and build dependencies. Archive validation checks smolvm compatibility, not image authenticity. The cache is keyed by the current local image ID, image reference, and platform, so a newly pulled image does not silently reuse an old archive.

## Image Builds and Publishing

`Dockerfile` includes Node.js 24, pinned Pi and omp releases, Python, uv, DuckDB, git, ripgrep, build tools, zsh, nftables, and util-linux. System Python supplies SQLite snapshots; `nft` installs the kernel policy and `setpriv` confines workload capabilities. No host Python dependency is required.

The launcher first exports with `docker save`. If that archive is incompatible with smolvm, it uses buildx's **Docker** exporter, not an OCI archive. Export failures stop launch; replacement of the cached archive happens only after a successful export and compatibility check. Existing buildx builders are not selected, created, or deleted by the launcher. Registry-backed export fallback uses an immutable digest. A local-only image needs a selected Docker-driver builder if `docker save` cannot export it.

`.github/workflows/build-image.yml` builds amd64 and arm64 images and publishes `latest` plus the commit SHA when the image sources or workflow change. Image sources include both Python entrypoints and `sandbox-network.json`. It requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. The host-side Smolfile must remain beside the launcher.

Local and CI publishing use BuildKit's registry exporter with `compression=zstd`, `compression-level=22`, `force-compression=true`, and `oci-mediatypes=true`. Level 22 favors smaller registry layers over export CPU time; `force-compression` also recompresses inherited layers. These settings affect published OCI layers, not necessarily the size of the local Docker-format archive used by smolvm.

`build.sh` is for deliberate multi-platform publishing, not a local-only build:

```bash
./build.sh                      # Builds and pushes latest, both platforms
./build.sh v1.0                  # Builds and pushes a specific tag
PLATFORMS=linux/amd64 ./build.sh  # Builds and pushes one platform
```

## Verification

```bash
./verify-guest.sh
```

This builds the working tree without publishing and boots disposable microVMs using only synthetic configuration. Kernel network fixtures prove allowed destination/port paths and count rejected IPv4 and IPv6 tailnet packets. Workload checks prove nftables and raw-packet bypass are denied while host-owned workspace files remain editable. The suite also checks separate agent roots, private permissions, omitted runtime trees and symlinks, read-only host sources, committed SQLite WAL snapshots, consistent backups during concurrent writes, preserved VM edits across nested shells, and both agents' versions.

Real Pi session APIs and the real omp CLI create, discover, and continue native transcripts across separate VMs. omp default and named profiles replay prior turns and image blobs through a local synthetic model provider. The host observes transcripts, artifacts, and blobs before the first VM exits. A cold-config consumer stage uses the pinned Linux agents at native host paths, without seeding or a shared SQLite index; it does not require host-installed agents. The suite never mounts your real `~/.pi` or `~/.omp`. Failed runs retain their synthetic fixture directory for diagnosis.

To use an existing Docker-format image archive:

```bash
SANDBOX_VERIFY_IMAGE_TAR=/path/to/image.tar ./verify-guest.sh
```

## Files

- `Dockerfile`: guest image and entrypoint.
- `sandbox.sh`: host launcher and mount validation.
- `sandbox-vm.py`: reuse or attach to a project's VM, reclaim abandoned VMs.
- `vm-seed.py`: private, per-agent configuration snapshots.
- `vm-network.py`: pinned tailnet HTTPS exception and kernel egress policy.
- `sandbox-network.json`: permitted tailnet hostname and TCP port.
- `sandbox.smolfile`: trusted per-VM network initialization.
- `sandbox.json.autonomous`: Pi sandbox extension policy.
- `verify-guest.sh`: real-guest security smoke checks.
- `build.sh`: multi-platform build and registry publishing.
- `.github/workflows/build-image.yml`: automated image publishing.
