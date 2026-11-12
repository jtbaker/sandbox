#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="${SANDBOX_IMAGE-jasonbaker/sandbox:latest}"
AGENT="${AGENT-pi}"
SSH_AGENT=false
DNS_SERVER=""
# The image's TERM, kept in step with Dockerfile.
VM_TERM=xterm-256color
TARGET_SET=false

# Validate all user-controlled launch settings before Docker or VM activity.
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            echo "Usage: sandbox [options] [target_directory]"
            echo "Starts an interactive login shell inside an ephemeral smolvm microVM."
            echo "Pi and omp sessions/attachments share normal host history and survive VM exit."
            echo "Do not edit the same session from multiple host/VM processes at once."
            echo ""
            echo "Options:"
            echo "  --agent NAME        Startup hint: pi (default) or omp; does not launch it."
            echo "  --ssh-agent         Opt in to forwarding the socket in SSH_AUTH_SOCK."
            echo "  --dns IP            Guest DNS resolver (default 100.100.100.100, the"
            echo "                      Tailscale resolver; pass a public resolver to override)."
            echo "  -h, --help          Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  AGENT               Startup hint: pi or omp (--agent overrides)."
            echo "  SANDBOX_IMAGE    Use an existing local image instead of pulling latest."
            echo "                      Export fallback may fetch its immutable registry digest."
            echo "  TERM                Passed to the guest when it names a terminal the guest"
            echo "                      can drive (xterm*, screen*, tmux*, vt100, vt102, linux);"
            echo "                      otherwise the guest uses $VM_TERM."
            echo "  LLM_BASE_URL        Custom endpoint; disables cloud API key forwarding."
            echo "  ANTHROPIC_API_KEY   Forwarded only when LLM_BASE_URL is empty."
            echo "  OPENAI_API_KEY      Forwarded only when LLM_BASE_URL is empty."
            echo "  SSH_AUTH_SOCK       Socket forwarded only with --ssh-agent."
            echo ""
            echo "Requires smolvm with privileged init/--no-init-cache, Docker, and realpath."
            exit 0
            ;;
        --agent)
            if [[ $# -lt 2 || ( "$2" != pi && "$2" != omp ) ]]; then
                echo "Error: --agent must be 'pi' or 'omp'." >&2
                exit 1
            fi
            AGENT="$2"
            shift 2
            ;;
        --ssh-agent)
            SSH_AGENT=true
            shift
            ;;
        --dns)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "Error: --dns requires a resolver IP address." >&2
                exit 1
            fi
            DNS_SERVER="$2"
            shift 2
            ;;
        --)
            shift
            if [[ $# -gt 1 || ( $# -eq 1 && "$TARGET_SET" == true ) ]]; then
                echo "Error: only one target directory is allowed." >&2
                exit 1
            fi
            if [[ $# -eq 1 ]]; then
                TARGET_ARG="$1"
                TARGET_SET=true
                shift
            fi
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [[ "$TARGET_SET" == true ]]; then
                echo "Error: only one target directory is allowed." >&2
                exit 1
            fi
            TARGET_ARG="$1"
            TARGET_SET=true
            shift
            ;;
    esac
done

if [[ "$AGENT" != pi && "$AGENT" != omp ]]; then
    echo "Error: AGENT must be 'pi' or 'omp'." >&2
    exit 1
fi
if [[ ! "$IMAGE_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9._/@:-]*$ ]]; then
    echo "Error: SANDBOX_IMAGE must be a nonempty Docker image reference." >&2
    exit 1
fi
if ! command -v realpath >/dev/null 2>&1; then
    echo "Error: realpath is required to validate host mounts." >&2
    exit 1
fi

# Reject separators both before and after canonicalization: command substitution
# strips trailing newlines, and symlinks can introduce otherwise hidden paths.
validate_mount_path() {
    if [[ -z "$1" || "$1" == *:* || "$1" == *$'\n'* || "$1" == *$'\r'* ]]; then
        echo "Error: mount paths must be nonempty and contain no colons or newlines." >&2
        exit 1
    fi
}

TARGET_PATH="${TARGET_ARG-.}"
validate_mount_path "$TARGET_PATH"
validate_mount_path "${HOME:-}"
# A sentinel preserves trailing newlines in realpath's result for validation.
if ! TARGET_RESULT=$(realpath -- "$TARGET_PATH" && printf '.'); then
    echo "Error: could not canonicalize the workspace directory." >&2
    exit 1
fi
TARGET_DIR="${TARGET_RESULT%$'\n'.}"
if ! HOME_RESULT=$(realpath -- "$HOME" && printf '.'); then
    echo "Error: could not canonicalize HOME." >&2
    exit 1
fi
HOST_HOME="${HOME_RESULT%$'\n'.}"
validate_mount_path "$TARGET_DIR"
validate_mount_path "$HOST_HOME"
if [[ ! -d "$TARGET_DIR" || ! -d "$HOST_HOME" ]]; then
    echo "Error: workspace and HOME must be existing directories." >&2
    exit 1
fi

HOST_PI_DIR="${HOST_HOME%/}/.pi"
HOST_OMP_DIR="${HOST_HOME%/}/.omp"
for CONFIG in "$HOST_PI_DIR" "$HOST_OMP_DIR"; do
    if [[ -e "$CONFIG" || -L "$CONFIG" ]]; then
        if ! CONFIG_RESULT=$(realpath -- "$CONFIG" && printf '.'); then
            echo "Error: could not canonicalize a host agent config directory." >&2
            exit 1
        fi
        CONFIG_DIR="${CONFIG_RESULT%$'\n'.}"
        validate_mount_path "$CONFIG_DIR"
        if [[ ! -d "$CONFIG_DIR" ]]; then
            echo "Error: host agent config paths must resolve to directories." >&2
            exit 1
        fi
    else
        CONFIG_DIR="$CONFIG"
    fi
    if [[ "$CONFIG" == "$HOST_PI_DIR" ]]; then
        CANONICAL_PI_DIR="$CONFIG_DIR"
    else
        CANONICAL_OMP_DIR="$CONFIG_DIR"
    fi
    if [[ "$TARGET_DIR" == "$CONFIG_DIR" || "$TARGET_DIR" == / || "$CONFIG_DIR" == / ||
          "$TARGET_DIR" == "$CONFIG_DIR/"* || "$CONFIG_DIR" == "$TARGET_DIR/"* ]]; then
        echo "Error: workspace must not overlap host .pi or .omp config directories." >&2
        exit 1
    fi
done
if [[ "$TARGET_DIR" == "$HOST_HOME" || "$HOST_HOME" == "$TARGET_DIR/"* ]]; then
    echo "Error: workspace must not be HOME or one of its ancestors." >&2
    exit 1
fi
HOST_PI_DIR="$CANONICAL_PI_DIR"
HOST_OMP_DIR="$CANONICAL_OMP_DIR"

# Mirror native path identities without mounting HOME or the host temporary tree.
HOST_TMP_PATH="${TMPDIR:-/tmp}"
validate_mount_path "$HOST_TMP_PATH"
if ! TMP_RESULT=$(realpath -- "$HOST_TMP_PATH" && printf '.'); then
    echo "Error: could not canonicalize TMPDIR." >&2
    exit 1
fi
HOST_TMPDIR="${TMP_RESULT%$'\n'.}"
validate_mount_path "$HOST_TMPDIR"
if [[ ! -d "$HOST_TMPDIR" ]]; then
    echo "Error: TMPDIR must be an existing directory." >&2
    exit 1
fi
WORKSPACE_ALIAS=""
if [[ "$TARGET_DIR" == /private/tmp/* ]]; then
    ALIAS_PATH="${TARGET_DIR#/private}"
    if ALIAS_RESULT=$(realpath -- "$ALIAS_PATH" 2>/dev/null && printf '.'); then
        ALIAS_DIR="${ALIAS_RESULT%$'\n'.}"
        validate_mount_path "$ALIAS_DIR"
        if [[ "$ALIAS_DIR" == "$TARGET_DIR" ]]; then
            WORKSPACE_ALIAS="$ALIAS_PATH"
        fi
    fi
fi

# Each writable state source has only real directory components beneath the
# canonical config root. Never follow an agent/session/blob/profile symlink into
# credentials or configuration, and never change existing state permissions.
ensure_state_directory() {
    local path="$1" result canonical
    validate_mount_path "$path"
    if [[ -L "$path" || ( -e "$path" && ! -d "$path" ) ]]; then
        echo "Error: shared state paths must be real directories, not symlinks: $path" >&2
        exit 1
    fi
    if [[ ! -d "$path" ]]; then
        (umask 077; mkdir -m 700 -- "$path")
    fi
    if ! result=$(realpath -- "$path" && printf '.'); then
        echo "Error: could not canonicalize shared state directory: $path" >&2
        exit 1
    fi
    canonical="${result%$'\n'.}"
    validate_mount_path "$canonical"
    if [[ "$canonical" != "$path" ]]; then
        echo "Error: shared state directory has an aliased parent: $path" >&2
        exit 1
    fi
}

STATE_MOUNTS=()
add_agent_state() {
    local source="$1" destination="$2" blobs="$3"
    ensure_state_directory "$source"
    ensure_state_directory "$source/sessions"
    STATE_MOUNTS+=(-v "$source/sessions:$destination/sessions")
    if [[ "$blobs" == true ]]; then
        ensure_state_directory "$source/blobs"
        STATE_MOUNTS+=(-v "$source/blobs:$destination/blobs")
    fi
}

ensure_state_directory "$HOST_PI_DIR"
ensure_state_directory "$HOST_OMP_DIR"
add_agent_state "$HOST_PI_DIR/agent" "${HOST_HOME%/}/.pi/agent" false
add_agent_state "$HOST_OMP_DIR/agent" "${HOST_HOME%/}/.omp/agent" true
PROFILES_DIR="$HOST_OMP_DIR/profiles"
if [[ -e "$PROFILES_DIR" || -L "$PROFILES_DIR" ]]; then
    ensure_state_directory "$PROFILES_DIR"
    for PROFILE_DIR in "$PROFILES_DIR"/* "$PROFILES_DIR"/.[!.]* "$PROFILES_DIR"/..?*; do
        [[ -e "$PROFILE_DIR" || -L "$PROFILE_DIR" ]] || continue
        [[ -d "$PROFILE_DIR" || -L "$PROFILE_DIR" ]] || continue
        PROFILE_NAME="${PROFILE_DIR##*/}"
        if [[ ! "$PROFILE_NAME" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ||
              "$PROFILE_NAME" == *. || "$PROFILE_NAME" == default ||
              "$PROFILE_NAME" =~ ^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$ ]]; then
            echo "Error: invalid omp profile directory name: $PROFILE_NAME" >&2
            exit 1
        fi
        ensure_state_directory "$PROFILE_DIR"
        add_agent_state "$PROFILE_DIR/agent" \
            "${HOST_HOME%/}/.omp/profiles/$PROFILE_NAME/agent" true
    done
fi

SCRIPT_PATH=$(realpath -- "${BASH_SOURCE[0]}")
REPO_DIR="${SCRIPT_PATH%/*}"
SMOLFILE="$REPO_DIR/sandbox.smolfile"
if [[ ! -f "$SMOLFILE" ]]; then
    echo "Error: sandbox.smolfile must be beside the launcher for trusted network initialization." >&2
    exit 1
fi
SMOLVM_ARGS=(machine run -it --net --net-backend virtio-net --smolfile "$SMOLFILE" \
    --no-init-cache --unprivileged --mem 2048 --cpus 4 \
    --workdir "$TARGET_DIR" --env "HOME=$HOST_HOME" --env "TMPDIR=$HOST_TMPDIR" \
    --env SANDBOX_PERSIST_SESSIONS=1)
if [[ -n "$WORKSPACE_ALIAS" ]]; then
    SMOLVM_ARGS+=(--env "SANDBOX_WORKSPACE_ALIAS=$WORKSPACE_ALIAS")
fi
# smolvm forwards the host TERM, which overrides the image default. A host TERM
# of dumb, or a type absent from the guest database, leaves zle without key
# codes, and arrow keys stop moving through history. Pass the host type when it
# is a terminal the guest can drive; use the image type otherwise.
case "${TERM-}" in
    xterm*|screen*|tmux*|vt100|vt102|linux)
        SMOLVM_ARGS+=(--env "TERM=$TERM") ;;
    *)
        SMOLVM_ARGS+=(--env "TERM=$VM_TERM")
        if [[ -t 0 && "${TERM-}" != "$VM_TERM" ]]; then
            echo "Guest terminal set to $VM_TERM (host TERM=${TERM:-unset})." >&2
        fi ;;
esac
if [[ -z "$DNS_SERVER" ]]; then
    # The smolvm resolver forwards to public nameservers by default, and those
    # cannot answer MagicDNS names, so trusted init fails resolving
    # tailnetHost. 100.100.100.100 is Tailscale's resolver address: queries
    # outside the tailnet go to public nameservers anyway, so this stays the
    # default whether or not the host runs Tailscale.
    DNS_SERVER="100.100.100.100"
fi
if [[ -n "$DNS_SERVER" ]]; then
    SMOLVM_ARGS+=(--dns "$DNS_SERVER")
fi
if [[ "$SSH_AGENT" == true ]]; then
    if [[ -z "${SSH_AUTH_SOCK:-}" || ! -S "$SSH_AUTH_SOCK" ]]; then
        echo "Error: --ssh-agent requires SSH_AUTH_SOCK to name an existing Unix socket." >&2
        exit 1
    fi
    SMOLVM_ARGS+=(--ssh-agent)
fi

# Endpoints are passed unchanged; the kernel policy decides what is reachable.
VM_LLM_URL="${LLM_BASE_URL:-}"
if [[ -n "$VM_LLM_URL" ]]; then
    echo "Using custom LLM endpoint; cloud API keys will not be forwarded."
    export VM_LLM_URL
    SMOLVM_ARGS+=(--secret-env OPENAI_BASE_URL=VM_LLM_URL --secret-env LLM_BASE_URL=VM_LLM_URL)
else
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        SMOLVM_ARGS+=(--secret-env ANTHROPIC_API_KEY=ANTHROPIC_API_KEY)
    fi
    if [[ -n "${OPENAI_API_KEY:-}" ]]; then
        SMOLVM_ARGS+=(--secret-env OPENAI_API_KEY=OPENAI_API_KEY)
    fi
fi

for TOOL in smolvm docker; do
    if ! command -v "$TOOL" >/dev/null 2>&1; then
        echo "Error: required command not found: $TOOL" >&2
        exit 1
    fi
done

CACHE_DIR="${HOST_HOME%/}/.cache/sandbox"
IMAGE_TAR="$CACHE_DIR/sandbox.tar"
source "$REPO_DIR/lib/image.sh"
PULL_IMAGE=true
if [[ -n "${SANDBOX_IMAGE+x}" ]]; then
    PULL_IMAGE=false
fi
prepare_image_archive "$IMAGE_NAME" "$CACHE_DIR" "$REPO_DIR" "$PULL_IMAGE"

echo "Mounting host directory: $TARGET_DIR"
# Join before mount: a second terminal for this workspace gets a shell in the
# running VM, not a second VM. The join path must precede the read-only hook
# mounts because machine exec runs inside the already-mounted VM; its mounts
# came from the first launcher's flags. join-spec prints `join <vm>` only for
# an attached VM (live launcher); leaked and absent cases boot fresh, which
# keeps the pinned network policy current. The agent flag is a boot-time hint
# only: inside the existing VM, run either agent by hand.
JOIN_DECISION=$("$REPO_DIR/sandbox-vm.py" join-spec "$TARGET_DIR" 2>/dev/null || echo none)
if [[ "$JOIN_DECISION" == join\ * ]]; then
    JOIN_VM="${JOIN_DECISION#join }"
    if [[ "$AGENT" != pi ]]; then
        echo "Joining $JOIN_VM: it booted with pi; run $AGENT by hand when needed."
    else
        echo "Joining $JOIN_VM for this workspace; a login shell starts beside any console."
    fi
    # -i -t gives the joined shell its own pty (job control, zle). zsh needs
    # -i too: `zsh -l` with a tty still reports non-interactive, and
    # oh-my-zsh sets the theme (the 🔒 prefix rides on it) only under
    # `[[ -o interactive ]]`. Login ordering stays intact: profile scripts
    # run before zshrc.
    exec smolvm machine exec -i -t -w "$TARGET_DIR" --name "$JOIN_VM" /bin/zsh -i -l
fi
# Git runs hooks and hook-class helpers (fsmonitor, filters) without a
# prompt. A writable project mount lets guest work, or an untrusted clone's
# own git directory, plant a script that host git then executes as the host
# user. The read-only re-mounts below cover the hook locations git executes
# from inside the mount: default hooks, linked worktrees (.git/worktrees),
# and submodule repositories (.git/modules). Published bypasses (sandcastle
# #1010, the separate-git-dir/fsmonitor Cursor escape) show why one path is
# not enough. Commit, add, and diff still work: they need only objects, refs
# and index. Known-open paths are listed in README limits.
MOUNT_ARGS=(-v "$TARGET_DIR:$TARGET_DIR")
PROTECTED_PATHS=()
for candidate in ".git/hooks" ".git/worktrees" ".git/modules"; do
    [[ -d "$TARGET_DIR/$candidate" ]] && PROTECTED_PATHS+=("$candidate")
done
# Each linked worktree keeps its hooks in a sibling directory of its own
# config, so protect those hooks without covering config-adjacent files.
for worktree in "$TARGET_DIR"/.git/worktrees/*/hooks; do
    relative="${worktree#"$TARGET_DIR"/.git/worktrees/}"
    PROTECTED_PATHS+=(".git/worktrees/${relative%/hooks}/hooks")
done
if [[ ${#PROTECTED_PATHS[@]} -gt 0 ]]; then
    for candidate in "${PROTECTED_PATHS[@]}"; do
        # Skip literal non-matches from the worktree loop (no nullglob here).
        [[ -d "$TARGET_DIR/$candidate" ]] || continue
        MOUNT_ARGS+=(-v "$TARGET_DIR/$candidate:$TARGET_DIR/$candidate:ro")
    done
    echo "Read-only in guest: ${PROTECTED_PATHS[*]} (git execution paths)."
else
    echo "Note: no git metadata found in the workspace mount."
fi
echo "Starting an interactive shell. Sessions persist in normal host history."
echo "No agent starts on its own: run $AGENT (or the other) when ready."
smolvm "${SMOLVM_ARGS[@]}" \
    "${MOUNT_ARGS[@]}" \
    "${STATE_MOUNTS[@]}" \
    -v "$HOST_PI_DIR:/root/.pi-host:ro" \
    -v "$HOST_OMP_DIR:/root/.omp-host:ro" \
    --image "$IMAGE_TAR" \
    -- /usr/local/bin/vm-seed.py zsh -l
