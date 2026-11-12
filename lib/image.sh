#!/usr/bin/env bash

# smolvm requires a Docker archive, not an OCI index or zero-byte blob pointers.
# This is a compatibility check, not archive integrity/authenticity verification.
image_archive_is_complete() {
    local listing manifest size
    [[ -f "$1" ]] || return 1
    listing=$(tar -tf "$1" 2>/dev/null) || return 1
    [[ $'\n'"$listing"$'\n' == *$'\nmanifest.json\n'* ]] || return 1
    manifest=$(tar -xOf "$1" manifest.json 2>/dev/null) || return 1
    [[ -n "$manifest" ]] || return 1
    size=$(wc -c < "$1") || return 1
    [[ "$size" -gt 1048576 ]]
}

prepare_image_archive() (
    local image_name="$1" cache_dir="$2" repo_dir="$3" pull_image="$4"
    local image_tar="$cache_dir/sandbox.tar" image_id_file="$cache_dir/.image_id"
    local arch platform layout_key layout_version image_layout image_id cache_key
    local cached_key stage temp_tar saved source digest builder_info builder_driver
    local label value rest

    mkdir -p "$cache_dir"
    arch=$(uname -m)
    case "$arch" in
        x86_64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) echo "Error: unsupported host architecture: $arch" >&2; exit 1 ;;
    esac
    platform="linux/$arch"
    if [[ "$pull_image" == false ]]; then
        echo "Using local image override (skipping docker pull): $image_name"
    else
        docker pull --platform "$platform" "$image_name"
    fi
    # Reject images built for the old shared-directory/shell-seeder layout before
    # exporting or booting them. A fresh registry pull alone cannot update that code.
    layout_key="io.sandbox.config-layout"
    layout_version="separate-v4"
    if ! image_layout=$(docker image inspect --format "{{index .Config.Labels \"$layout_key\"}}" "$image_name"); then
        echo "Error: image is unavailable locally; SANDBOX_IMAGE requires an existing local image." >&2
        exit 1
    fi
    if [[ "$image_layout" != "$layout_version" ]]; then
        if [[ "$pull_image" == false ]]; then
            echo "Error: SANDBOX_IMAGE lacks the current configuration seeder; rebuild it from Dockerfile." >&2
            exit 1
        fi
        if [[ ! -f "$repo_dir/Dockerfile" || ! -f "$repo_dir/vm-seed.py" ||
              ! -f "$repo_dir/vm-network.py" || ! -f "$repo_dir/sandbox-network.json" ||
              ! -f "$repo_dir/sandbox.json.autonomous" ]]; then
            echo "Error: published image is too old; matching image sources must be beside the launcher." >&2
            exit 1
        fi
        image_name="sandbox:config-local"
        echo "Published image uses the old configuration layout; building the matching image locally (no push)."
        docker buildx build --load --platform "$platform" -f "$repo_dir/Dockerfile" \
            -t "$image_name" "$repo_dir"
        image_layout=$(docker image inspect --format "{{index .Config.Labels \"$layout_key\"}}" "$image_name")
        if [[ "$image_layout" != "$layout_version" ]]; then
            echo "Error: locally built image has an incompatible configuration layout." >&2
            exit 1
        fi
    fi
    if ! image_id=$(docker image inspect --format '{{.Id}}' "$image_name"); then
        echo "Error: image is unavailable locally; SANDBOX_IMAGE requires an existing local image." >&2
        exit 1
    fi
    if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "Error: Docker returned an invalid local image identity." >&2
        exit 1
    fi
    cache_key="$image_name|$image_id|$platform"

    cached_key=""
    if [[ -f "$image_id_file" ]]; then
        IFS= read -r cached_key < "$image_id_file" || cached_key=""
    fi
    if [[ "$cached_key" == "$cache_key" && -f "$image_tar" ]] && image_archive_is_complete "$image_tar"; then
        echo "Using image cache for current local image: $image_tar"
    else
        stage=$(mktemp -d "$cache_dir/.export.XXXXXX")
        trap 'rm -rf "$stage"' EXIT
        temp_tar="$stage/image.tar"
        echo "Exporting $image_name..."
        saved=false
        if docker save --output "$temp_tar" "$image_name"; then
            if image_archive_is_complete "$temp_tar"; then
                saved=true
            else
                echo "docker save produced an unusable archive; trying the buildx Docker exporter." >&2
            fi
        else
            echo "docker save failed; trying the buildx Docker exporter." >&2
        fi
        if [[ "$saved" != true ]]; then
            # Use the active builder unchanged. Isolated builders can fetch a pulled
            # registry image by immutable digest without relying on the local store.
            source=""
            if digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image_name" 2>/dev/null); then
                if [[ "$digest" =~ ^[a-zA-Z0-9][a-zA-Z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]]; then
                    source="$digest"
                fi
            fi
            if [[ -z "$source" ]]; then
                if [[ "$pull_image" == true ]]; then
                    echo "Error: pulled image has no immutable registry digest for buildx export." >&2
                    exit 1
                fi
                builder_info=$(docker buildx inspect)
                builder_driver=""
                while read -r label value rest; do
                    if [[ "$label" == Driver: ]]; then
                        builder_driver="$value"
                    fi
                done <<< "$builder_info"
                if [[ "$builder_driver" != docker ]]; then
                    echo "Error: local-only image export needs an existing docker-driver builder; select one or use a registry-backed image." >&2
                    exit 1
                fi
                source="$image_name"
            fi
            mkdir "$stage/context"
            printf 'FROM %s\n' "$source" > "$stage/context/Dockerfile"
            rm -f "$temp_tar"
            if ! docker buildx build --platform "$platform" --output "type=docker,dest=$temp_tar" "$stage/context"; then
                echo "Error: buildx Docker archive export failed; cache was not updated." >&2
                exit 1
            fi
            if ! image_archive_is_complete "$temp_tar"; then
                echo "Error: exported archive is unusable; cache was not updated." >&2
                exit 1
            fi
        fi
        printf '%s\n' "$cache_key" > "$stage/image_id"
        mv -f "$temp_tar" "$image_tar"
        mv -f "$stage/image_id" "$image_id_file"
        rm -rf "$stage"
        trap - EXIT
    fi
)
