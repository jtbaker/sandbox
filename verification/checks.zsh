set -eu
setopt PIPE_FAIL
workspace="$PWD"
fail() { print -r -- "FAIL: $1" > "$workspace/failure"; exit 1; }
pass() { print -r -- "PASS: $1" >> "$workspace/assertions"; }
trap 'print -r -- "FAIL: guest assertion or command failed" > "$workspace/failure"' ZERR
mode="$1"
/usr/bin/python3 /verify/network-fixtures.py workload >> "$workspace/assertions" \
    || fail 'network filter proof or capability-drop contract failed'
[[ ${+PI_CODING_AGENT_DIR} == 0 && ${+PI_CODING_AGENT_SESSION_DIR} == 0 ]] \
    || fail 'global agent/session directory override is set'
[[ "$HOME" == "$PI_VERIFY_HOME" && "$TMPDIR" == "$PI_VERIFY_TMPDIR" ]] \
    || fail 'canonical HOME or TMPDIR was not mirrored'
[[ "$PWD" == "$PI_VERIFY_WORKSPACE" && "$PWD" != /workspace ]] || fail 'canonical workspace was not mirrored'
[[ "$SANDBOX_PERSIST_SESSIONS" == 1 ]] || fail 'persistent session boot flag missing'
[[ -d "$HOME/.pi/agent" && -d "$HOME/.omp/agent" ]] || fail 'native agent directories missing'
[[ ! -L "$HOME/.pi" && ! -L "$HOME/.omp" && ! -e "$HOME/.pi-agent" ]] || fail 'config roots are not separate native directories'
/usr/bin/python3 /verify/sessions.py policy || fail 'Pi autonomous sandbox policy missing or changed'
[[ ! -e "$HOME/.omp/agent/sandbox.json" ]] || fail 'Pi sandbox profile leaked into omp config'
pass "$mode: mirrored HOME, TMPDIR, cwd and independent native config paths"

# Mounted state retains its original modes; only private config is hardened.
/usr/bin/python3 /verify/sessions.py structure "$mode" || fail 'native state mounts or private config permissions failed'
pass "$mode: exact RW state mounts preserve contents and modes; private config has no symlinks"

if [[ "$mode" != default ]]; then
    /usr/bin/python3 /verify/sqlite-fixtures.py check \
        || fail 'SQLite backup omitted committed WAL data, copied sidecars, or failed quick_check'
    pass 'fixture: private SQLite snapshots include committed WAL data and pass quick_check'
    for agent in pi omp; do
        root="$HOME/.$agent"
        src="/root/.$agent-host"
        [[ "$(< "$root/config-origin.json")" == "{\"origin\":\"$agent-root\"}" ]] || fail 'same-named root config was merged or lost'
        [[ "$(< "$root/agent/config-origin.json")" == "{\"origin\":\"$agent-agent\"}" ]] || fail 'same-named agent config was merged or lost'
        [[ "$(< "$root/profiles/work/config.json")" == "{\"origin\":\"$agent-profile\"}" ]] || fail 'named profile was not copied'
        cmp -s "$src/root-config.txt" "$root/root-config.txt" || fail 'root-level configuration not copied'
        cmp -s "$src/agent/extensions/nested/config.txt" "$root/agent/extensions/nested/config.txt" || fail 'nested configuration not copied'
        cmp -s "$src/agent/extensions/run/config.txt" "$root/agent/extensions/run/config.txt" \
            || fail 'portable extension directory named run was incorrectly excluded'
        for config_root in "$root" "$root/profiles/work"; do
            for runtime in run ssh-control puppeteer natives .supervisor; do
                [[ ! -e "$config_root/$runtime" ]] || fail 'host daemon/browser/native runtime tree copied'
            done
        done
        [[ "$(stat -c %a "$root/agent/extensions/fixture-tool.sh")" == 700 ]] || fail 'copied executable is not private 0700'
        [[ "$(stat -c %a "$root/root-config.txt")" == 600 ]] || fail 'copied ordinary file is not private 0600'
        for level in "$root" "$root/agent" "$root/agent/extensions/nested"; do
            for excluded in sessions terminal-sessions cache caches logs bin __pycache__ .git history.db history.db-wal history.db-shm history.db.backup trust.json trust.db trust.db-wal fixture.db-wal fixture.db-shm .seeded; do
                [[ "$level/$excluded" == "$root/agent/sessions" ]] && continue
                [[ ! -e "$level/$excluded" && ! -L "$level/$excluded" ]] || fail 'non-mounted host history, binaries, cache, or trust copied'
            done
        done
        for link in "$root/symlink-file" "$root/symlink-directory" "$root/broken-symlink" "$root/agent/relative-symlink-file" "$root/agent/relative-symlink-directory"; do
            [[ ! -e "$link" && ! -L "$link" ]] || fail 'symlink was followed or copied'
        done
        if (print -r -- forbidden > "$src/write-probe") 2>/dev/null; then
            fail 'source mount allowed file creation'
        fi
        if (print -r -- forbidden > "$src/config-origin.json") 2>/dev/null; then
            fail 'source mount allowed existing file modification'
        fi
        if rm "$src/read-only-marker" 2>/dev/null; then
            fail 'source mount allowed file deletion'
        fi
        if chmod 0600 "$src/config-origin.json" 2>/dev/null; then
            fail 'source mount allowed metadata modification'
        fi
        command -v mount >/dev/null || fail 'mount command is required for the remount regression'
        if mount -o remount,rw "$src" 2>/dev/null; then
            fail 'restricted guest remounted a host config source writable'
        fi
        if (print -r -- forbidden >> "$src/read-only-marker") 2>/dev/null; then
            fail 'source mount allowed writes after remount attempt'
        fi
    done
    pass 'fixture: same-named Pi and omp config, root files, and named profiles stay separate'
    pass 'fixture: only native mounted sessions survive; arbitrary nested sessions and private runtime state omitted'
    pass "$mode: host runtime trees omitted while portable extension run directories survive"
    pass "$mode: source mounts reject writes and metadata changes, including after remount attempts"
    # Nested login shells remain supported; privileged nested bubblewrap does
    # not, because restoring NET_ADMIN/SYS_ADMIN would undermine the filter.

    for agent in pi omp; do
        print -r -- '{"origin":"vm-edit"}' > "$HOME/.$agent/config-origin.json"
        print -r -- '{"origin":"vm-edit"}' > "$HOME/.$agent/agent/config-origin.json"
        touch -t 200001010000 "$HOME/.$agent/config-origin.json" "$HOME/.$agent/agent/config-origin.json"
        rm "$HOME/.$agent/agent/deletable.txt"
    done
    print '' >> "$HOME/.pi/agent/sandbox.json"
    cp "$HOME/.pi/agent/sandbox.json" "$workspace/edited-sandbox.json"
    /usr/bin/python3 /verify/sessions.py shell '
        set -eu
        [[ ${+PI_CODING_AGENT_DIR} == 0 ]]
        uv --version >/dev/null
        for agent in pi omp; do
            [[ "$(< "$HOME/.$agent/config-origin.json")" == "{\"origin\":\"vm-edit\"}" ]]
            [[ "$(< "$HOME/.$agent/agent/config-origin.json")" == "{\"origin\":\"vm-edit\"}" ]]
            [[ ! -e "$HOME/.$agent/agent/deletable.txt" ]]
        done
        cmp -s "$HOME/.pi/agent/sandbox.json" "$PWD/edited-sandbox.json"
    ' || fail 'interactive login zsh failed or changed private config'
    pass 'fixture: clean interactive login zsh finds image tools and preserves VM edits'
else
    [[ ! -e "$HOME/.pi/config-origin.json" && ! -e "$HOME/.omp/config-origin.json" ]] || fail 'unmounted boot retained fixture config'
    print -r -- synthetic > "$HOME/.pi/agent/default-write-probe"
    print -r -- synthetic > "$HOME/.omp/agent/default-write-probe"
    pass 'default: boot without host config mounts provides writable native config'
    /usr/bin/python3 /verify/sqlite-fixtures.py stress \
        || fail 'configuration snapshot cannot finish consistently under ongoing host writes'
    pass 'default: configuration snapshot completes consistently while source writes continue'
fi

for agent in pi omp; do
    command -v "$agent" >/dev/null || fail "$agent command is missing"
    version="$(timeout 30 "$agent" --version 2>/dev/null)" || fail "$agent --version failed"
    case "$agent:$version" in
        pi:*1.5.2*|omp:*18.18.9*) ;;
        *) fail "$agent does not match the pinned verifier API version" ;;
    esac
done
pass "$mode: actual pi --version and omp --version succeed"
if [[ "$mode" == fixture || "$mode" == resume ]]; then
    /usr/bin/python3 /verify/sessions.py "$mode" || fail 'real-agent session persistence or resume failed'
    pass "$mode: real Pi and omp default/profile sessions use native buckets, artifacts and image blobs"
fi
print -r -- "$mode-complete" > "$workspace/completed"
