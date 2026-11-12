#!/usr/bin/env bash
# Build and boot the working tree without publishing. Only synthetic host
# configuration and session state are mounted; real ~/.pi and ~/.omp stay untouched.
# Reuse a local Docker archive with SANDBOX_VERIFY_IMAGE_TAR=/path/image.tar.
set -euo pipefail

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_UID=$(id -u)
SANDBOX_GID=$(id -g)
[[ "$SANDBOX_UID" != 0 && "$SANDBOX_UID" != 65532 ]] || fail 'run verification as a non-root user other than the reserved DNS user'
TMP="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-verify.XXXXXXXX")"
TMP="$(cd "$TMP" && pwd -P)"
HOST_HOME="$TMP/home"
HOST_TMPDIR="$TMP/native-tmp"
export PI_VERIFY_HOME="$HOST_HOME" PI_VERIFY_TMPDIR="$HOST_TMPDIR"
ACTIVE_VM=""
cleanup() {
    local result=$?
    if [[ -n "$ACTIVE_VM" ]]; then
        kill "$ACTIVE_VM" 2>/dev/null || true
        wait "$ACTIVE_VM" 2>/dev/null || true
    fi
    if [[ "$result" != 0 ]]; then
        printf 'Synthetic fixture diagnostics retained at %s\n' "$TMP" >&2
    else
        rm -rf -- "$TMP"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'printf "FAIL: verifier command failed at line %s\n" "$LINENO" >&2' ERR

command -v smolvm >/dev/null 2>&1 || fail 'smolvm is required'
IMAGE_TAR="${SANDBOX_VERIFY_IMAGE_TAR:-}"
if [[ -n "$IMAGE_TAR" ]]; then
    [[ -f "$IMAGE_TAR" ]] || fail 'SANDBOX_VERIFY_IMAGE_TAR is not a file'
    IMAGE_TAR="$(cd "$(dirname "$IMAGE_TAR")" && pwd)/$(basename "$IMAGE_TAR")"
else
    command -v docker >/dev/null 2>&1 || fail 'docker with buildx is required'
    case "$(uname -m)" in
        arm64|aarch64) ARCH=arm64 ;;
        x86_64|amd64) ARCH=amd64 ;;
        *) fail 'unsupported host architecture' ;;
    esac
    IMAGE_TAR="$TMP/image.tar"
    # Use the existing selected builder without creating, selecting, or removing
    # any builder. Docker output embeds the manifest and layers smolvm needs.
    if ! docker buildx build --progress quiet --platform "linux/$ARCH" \
        -f "$REPO/Dockerfile" --output "type=docker,dest=$IMAGE_TAR" \
        "$REPO" > "$TMP/build.log" 2>&1; then
        fail 'working-tree Docker image build failed'
    fi
    printf 'PASS: working-tree image built locally without publishing\n'
fi
if ! tar -tf "$IMAGE_TAR" > "$TMP/archive-members" 2>/dev/null; then
    fail 'image archive cannot be read'
fi
grep -Eq '^(\./)?manifest\.json$' "$TMP/archive-members" \
    || fail 'image archive is not Docker-compatible (manifest.json missing)'
printf 'PASS: Docker-compatible image archive\n'

mkdir -p "$TMP/fixtures" "$TMP/control" "$HOST_HOME/project" "$HOST_TMPDIR" "$TMP/default-workspace" "$TMP/preparation-workspace"
for workspace in "$HOST_HOME/project" "$TMP/default-workspace" "$TMP/preparation-workspace"; do
    printf 'host workspace content\n' > "$workspace/editable-host-file"
done
printf '{"tailnetHost":"100.64.0.10","httpsPort":443,"blockedDomainSuffixes":["aliyuncs.com"],"blockedASNs":[],"feedMaxAgeHours":168}\n' > "$TMP/control/network.json"
cp "$REPO/verification/Smolfile" "$TMP/Smolfile"
cp "$REPO/verification/network-fixtures.py" "$TMP/control/network-fixtures.py"
cp "$REPO/verification/sqlite-fixtures.py" "$TMP/control/sqlite-fixtures.py"
cp "$REPO/verification/pi-sessions.mjs" "$TMP/control/pi-sessions.mjs"
cp "$REPO/verification/sessions.py" "$TMP/control/sessions.py"
cp "$REPO/verification/checks.zsh" "$TMP/control/checks.zsh"
# Deliberately permissive sources ensure private copies are not just inheriting
# safe host modes. These are markers, not credentials or executable host tools.
for agent in pi omp; do
    root="$TMP/fixtures/$agent"
    mkdir -p "$root/agent/extensions/nested" "$root/profiles/work"
    printf '{"origin":"%s-root"}\n' "$agent" > "$root/config-origin.json"
    printf '{"origin":"%s-agent"}\n' "$agent" > "$root/agent/config-origin.json"
    printf '{"origin":"%s-profile"}\n' "$agent" > "$root/profiles/work/config.json"
    printf 'synthetic root config\n' > "$root/root-config.txt"
    printf 'synthetic nested config\n' > "$root/agent/extensions/nested/config.txt"
    mkdir -p "$root/agent/extensions/run"
    printf 'portable extension source\n' > "$root/agent/extensions/run/config.txt"
    for config_root in "$root" "$root/profiles/work"; do
        for runtime in run ssh-control puppeteer natives .supervisor; do
            mkdir -p "$config_root/$runtime"
            printf 'host process state\n' > "$config_root/$runtime/fixture-marker"
        done
    done
    printf 'synthetic removable config\n' > "$root/agent/deletable.txt"
    printf 'synthetic read-only marker\n' > "$root/read-only-marker"
    printf '#!/bin/sh\nexit 0\n' > "$root/agent/extensions/fixture-tool.sh"
    printf '{}\n' > "$root/agent/settings.json"
    printf '{}\n' > "$root/agent/auth.json"
    printf '{}\n' > "$root/agent/config.yml"
    # A valid empty provider map does not point agents at any host service.
    printf '{"providers":{}}\n' > "$root/agent/models.json"
    # Real SQLite coverage lives at root state.db, never at an agent-owned
    # database path. History database markers below must always be excluded.
    for level in "$root" "$root/agent" "$root/agent/extensions/nested"; do
        for excluded in sessions terminal-sessions cache caches logs bin __pycache__ .git; do
            mkdir -p "$level/$excluded"
            printf 'must not be copied\n' > "$level/$excluded/fixture-marker"
        done
        for excluded in history.db history.db-wal history.db-shm history.db.backup trust.json trust.db trust.db-wal fixture.db-wal fixture.db-shm .seeded; do
            printf 'must not be copied\n' > "$level/$excluded"
        done
    done
    ln -s /etc/passwd "$root/symlink-file"
    ln -s /etc "$root/symlink-directory"
    ln -s absent-target "$root/broken-symlink"
    ln -s extensions/nested/config.txt "$root/agent/relative-symlink-file"
    ln -s trust.json "$root/agent/trust-alias.json"
    ln -s sessions/fixture-marker "$root/agent/session-alias.json"
    ln -s extensions "$root/agent/relative-symlink-directory"
    find "$root" -type d -exec chmod 0777 {} +
    find "$root" -type f -exec chmod 0666 {} +
    chmod 0777 "$root/agent/extensions/fixture-tool.sh"
done
ln -s "$HOST_HOME/.pi/agent/models.json" "$TMP/fixtures/omp/agent/models.yml"
# State is intentionally separate from read-only configuration fixtures, so the
# final byte-for-byte config comparison excludes legitimate transcript writes.
for state in "$HOST_HOME/.pi/agent/sessions" \
    "$HOST_HOME/.omp/agent/sessions" "$HOST_HOME/.omp/agent/blobs" \
    "$HOST_HOME/.omp/profiles/work/agent/sessions" "$HOST_HOME/.omp/profiles/work/agent/blobs"; do
    mkdir -p "$state"
    printf 'mounted state is not a private config copy\n' > "$state/mount-marker"
    chmod 0777 "$state"
    chmod 0666 "$state/mount-marker"
done
printf 'host HOME is not a volume\n' > "$HOST_HOME/private-home-marker"
mkdir -p "$TMP/fixtures/omp/profiles/work/agent"
printf '{}\n' > "$TMP/fixtures/omp/profiles/work/agent/config.yml"

# Prepare genuine live-WAL snapshots using only the image's Python standard
# library. Writable host mounts contain only disposable synthetic fixtures.
if ! (cd "$TMP" && smolvm machine run --unprivileged --net-backend virtio-net \
    --smolfile "$TMP/Smolfile" --dns 100.64.0.10 --no-init-cache --timeout 120s --mem 2048 --cpus 2 \
    --env "SANDBOX_UID=$SANDBOX_UID" --env "SANDBOX_GID=$SANDBOX_GID" \
    --workdir "$TMP/preparation-workspace" -v "$TMP/control:/verify:ro" \
    -v "$TMP/preparation-workspace:$TMP/preparation-workspace" \
    -v "$TMP/fixtures:/fixtures" --image "$IMAGE_TAR" \
    -- /usr/bin/setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
    --clear-groups --reuid "$SANDBOX_UID" --regid "$SANDBOX_GID" --no-new-privs \
    /usr/bin/python3 /verify/sqlite-fixtures.py prepare) \
    > "$TMP/sqlite-preparation.log" 2>&1; then
    if [[ -f "$TMP/preparation-workspace/failure" ]]; then
        IFS= read -r detail < "$TMP/preparation-workspace/failure"
        fail "SQLite preparation: $detail"
    fi
    fail 'SQLite WAL fixture preparation boot failed'
fi
[[ -f "$TMP/fixtures/sqlite-prepared" ]] || fail 'SQLite WAL fixture preparation did not finish'
printf 'PASS: genuine committed SQLite WAL fixtures prepared without host dependencies\n'
# Byte-for-byte snapshots also cover file modes, symlinks, names and mtimes.
# Reading a file may update atime, which ordinary tar headers do not include.
COPYFILE_DISABLE=1 tar -cf "$TMP/fixtures-before.tar" -C "$TMP/fixtures" pi omp

printf '#!/usr/bin/env bash\nexport HOME=%q\nexec smolvm "$@"\n' "$HOME" > "$TMP/host-smolvm"
chmod 0700 "$TMP/host-smolvm"
HOME="$HOST_HOME" "$REPO/sandbox-vm.py" record-image "$IMAGE_TAR"

run_guest() {
    local mode="$1" workspace="$2" result=0 detail vm_pid attempt ready=0 path
    shift 2
    local args=(machine run --unprivileged --net-backend virtio-net
        --smolfile "$TMP/Smolfile" --dns 100.64.0.10 --no-init-cache --timeout 240s --mem 2048 --cpus 2
        --workdir "$workspace" --env "HOME=$HOST_HOME" --env "TMPDIR=$HOST_TMPDIR"
        --env "PI_VERIFY_HOME=$HOST_HOME" --env "PI_VERIFY_TMPDIR=$HOST_TMPDIR"
        --env "PI_VERIFY_WORKSPACE=$workspace" --env SANDBOX_PERSIST_SESSIONS=1
        --env "SANDBOX_UID=$SANDBOX_UID" --env "SANDBOX_GID=$SANDBOX_GID")
    local state
    for state in .pi/agent/sessions .omp/agent/sessions .omp/agent/blobs \
        .omp/profiles/work/agent/sessions .omp/profiles/work/agent/blobs; do
        [[ "$mode" == default && "$state" == .omp/profiles/* ]] && continue
        args+=(-v "$HOST_HOME/$state:$HOST_HOME/$state")
    done
    local command=(/usr/local/bin/vm-seed.py zsh -l -c 'source /verify/checks.zsh "$1"' verify "$mode")
    if [[ "$mode" == host ]]; then
        # Same native namespace without seeding, snapshots or a shared index.
        # The image supplies pinned agents; no host tool installation is needed.
        command=(/usr/bin/python3 /verify/sessions.py host-prepare)
    fi
    rm -f "$workspace/failure" "$workspace/completed" "$workspace/assertions" \
        "$workspace/live-ready" "$workspace/host-observed"
    (cd "$TMP" && smolvm "${args[@]}" \
        -v "$TMP/control:/verify:ro" -v "$workspace:$workspace" \
        "$@" --image "$IMAGE_TAR" -- "${command[@]}") \
        > "$TMP/$mode-boot.log" 2>&1 &
    vm_pid=$!
    ACTIVE_VM="$vm_pid"
    if [[ "$mode" == fixture ]]; then
        # Wait after real agent writes, before VM exit: teardown-only copies
        # cannot satisfy this host observation and guest acknowledgement.
        for ((attempt = 0; attempt < 180; attempt++)); do
            if [[ -f "$workspace/live-ready" ]]; then ready=1; break; fi
            kill -0 "$vm_pid" 2>/dev/null || break
            sleep 1
        done
        if [[ "$ready" == 1 ]]; then
            [[ -s "$workspace/live-paths" ]] || fail 'guest omitted live native state paths'
            while IFS= read -r path; do
                [[ "$path" == "$HOST_HOME/"* && -s "$path" ]] \
                    || fail 'live VM state is not readable at its native host path'
                case "$path" in
                    *.jsonl) grep -Eq 'fixture-pi-answer-fixture|fixture-answer-fixture-(omp|work)' "$path" \
                        || fail 'host cannot read real saved agent turn while VM is live' ;;
                    */blobs/*) [[ "$(shasum -a 256 "$path")" == "${path##*/} "* ]] \
                        || fail 'host image blob does not match its content address while VM is live' ;;
                    */local/fixture-artifact.txt) grep -Eq '^fixture-artifact-(omp|work)$' "$path" \
                        || fail 'host artifact is missing while VM is live' ;;
                    *) fail 'unexpected live fixture path' ;;
                esac
            done < "$workspace/live-paths"
            HOME="$HOST_HOME" SMOLVM="$TMP/host-smolvm" "$REPO/sandbox-vm.py" \
                attach --target "$workspace" -- /usr/bin/python3 /verify/network-fixtures.py joined \
                > "$TMP/attachment.log" 2>&1 \
                || fail 'independent host attachment lost non-root identity, privilege restrictions, or filtered DNS'
            printf 'PASS: independent host attachment preserves non-root identity, no_new_privs, zero actual capabilities, and filtered DNS\n'
            printf 'host observed live transcripts, artifacts and blobs\n' > "$workspace/host-observed"
            printf 'PASS: real-agent transcripts, artifacts and blobs are host-visible before VM exit\n'
        fi
    fi
    wait "$vm_pid" || result=$?
    ACTIVE_VM=""
    if [[ -f "$workspace/failure" ]]; then
        IFS= read -r detail < "$workspace/failure"
        case "$detail" in
            'FAIL: '*) fail "$mode: ${detail#FAIL: }" ;;
            *) fail "$mode: guest assertion failed" ;;
        esac
    fi
    [[ "$result" == 0 ]] || fail "$mode: smolvm boot or guest checks failed"
    [[ -f "$workspace/completed" ]] || fail "$mode: guest did not complete its assertions"
    [[ "$(< "$workspace/completed")" == "$mode-complete" ]] || fail "$mode: guest completion marker invalid"
    # Only our concise assertion records reach stdout, never VM logs/config.
    while IFS= read -r assertion; do
        case "$assertion" in
            'PASS: '*) printf '%s\n' "$assertion" ;;
            *) fail "$mode: unexpected guest assertion output" ;;
        esac
    done < "$workspace/assertions"
    [[ ! -e "$HOST_HOME/.omp/agent/history.db" \
        && ! -e "$HOST_HOME/.omp/profiles/work/agent/history.db" ]] \
        || fail 'VM history SQLite database leaked to host state'
}

run_guest fixture "$HOST_HOME/project" \
    -v "$TMP/fixtures/pi:/root/.pi-host:ro" \
    -v "$TMP/fixtures/omp:/root/.omp-host:ro"
run_guest resume "$HOST_HOME/project" \
    -v "$TMP/fixtures/pi:/root/.pi-host:ro" \
    -v "$TMP/fixtures/omp:/root/.omp-host:ro"
run_guest host "$HOST_HOME/project"
run_guest default "$TMP/default-workspace"
COPYFILE_DISABLE=1 tar -cf "$TMP/fixtures-after.tar" -C "$TMP/fixtures" pi omp
cmp -s "$TMP/fixtures-before.tar" "$TMP/fixtures-after.tar" \
    || fail 'synthetic host configuration changed'
printf 'PASS: synthetic host fixtures remain byte-for-byte unchanged\n'
