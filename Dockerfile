FROM node:24-slim
LABEL io.sandbox.config-layout="separate-v5"

# Install system utilities commonly needed by coding agents
# bubblewrap + socat are required by the sandbox extension for in-VM sandboxing
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ripgrep \
    build-essential \
    zsh \
    python3 \
    iproute2 \
    nftables \
    dnsmasq-base \
    util-linux \
    bubblewrap \
    socat \
    && rm -rf /var/lib/apt/lists/*

# --- Autonomous agent environment ------------------------------------------------
# Host configuration is read-only; each agent receives its own private snapshot.
# Seed once at the entrypoint, before any shell or agent can access the copies.
COPY vm-seed.py /usr/local/bin/vm-seed.py
COPY vm-network.py /usr/local/bin/vm-network.py
COPY --chmod=0644 network_policy.py /usr/local/bin/network_policy.py
COPY sandbox-network.json /opt/sandbox/network.json
COPY sandbox.json.autonomous /opt/sandbox/sandbox.json.autonomous
RUN chmod +x /usr/local/bin/vm-seed.py /usr/local/bin/vm-network.py
RUN groupadd --gid 65532 sandbox-dns && \
    useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin sandbox-dns

# Install Oh-My-Zsh (unattended)
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# Set UTF-8 locale so Unicode characters (e.g., λ in the prompt) render correctly
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# TERM is not inherited through the smolvm microVM console; default to xterm-256color
# so zsh's line editor (zle), terminfo key bindings, and TUI apps work in the container
ENV TERM=xterm-256color

# Fix backspace key (sets erase char to DEL \177)
RUN echo 'bindkey "\e[3~" delete-char' >> /root/.zshrc && \
    echo 'stty erase "\177"' >> /root/.zshrc

# Install uv (Python package manager)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install Python via uv and expose as `python` on the system path
RUN uv python install && ln -s $(uv python find 3.14 || uv python find 3.13 || uv python find 3.12) /usr/local/bin/python

# Install DuckDB CLI
RUN curl https://install.duckdb.org | sh

# Install the Pi coding agent globally (pin to a known-good release)
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent@1.5.2

# Install the omp (oh-my-pi) coding agent globally (pin to a known-good
# release, like the pi pin above). omp has a native Rust core; the official
# installer's --binary --ref mode fetches the prebuilt release binary for the
# target platform (linux/amd64 + linux/arm64 here) and verifies its sha256.
# omp uses /root/.omp/agent; Pi uses /root/.pi/agent. Do not set the shared
# PI_CODING_AGENT_DIR override, which would merge their configuration.
RUN curl -fsSL https://omp.sh/install | sh -s -- --binary --ref v18.18.9

# Native HOME links use these image tools without giving workloads write access.
RUN command -v pi && command -v omp && chmod 0755 /root && \
    for directory in /root/.local /root/.omp /root/.oh-my-zsh; do \
        if [ -d "$directory" ]; then chmod -R a+rX "$directory"; fi; \
    done

# Prefix the existing theme prompt without changing its contents.
RUN printf '\nPROMPT="🔒 $PROMPT"\n' >> /root/.zshrc

# The launcher mounts and selects the host project's native absolute path.
WORKDIR /

# Start an interactive shell only after configuration seeding succeeds.
ENTRYPOINT ["/usr/local/bin/vm-seed.py"]
CMD ["zsh", "-l"]
