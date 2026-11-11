FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates jq python3 python3-pip unzip nmap \
    && rm -rf /var/lib/apt/lists/*

# tiktoken for orgxray's BPE token-efficiency filter. Vocab (.tiktoken)
# lastes ned ved forste kall — den MA vare bakt inn, for runtime er
# --network none. Prewarmes i /opt/tiktoken-cache (world-readable).
ARG TIKTOKEN=0.13.0
RUN pip3 install --break-system-packages --no-cache-dir "tiktoken==${TIKTOKEN}" \
 && mkdir -p /opt/tiktoken-cache && chmod 755 /opt/tiktoken-cache \
 && TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache python3 -c \
    "import tiktoken; tiktoken.get_encoding('cl100k_base')" \
 && chmod -R a+rX /opt/tiktoken-cache
ENV TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache

# --- pinned tools (alle >7 dager gamle) ---
ARG GITLEAKS=8.30.1
ARG NUCLEI=3.11.1
ARG KATANA=1.8.0
ARG SUBFINDER=2.17.0

RUN set -e; cd /tmp \
 && curl -sL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS}/gitleaks_${GITLEAKS}_linux_x64.tar.gz" | tar xz gitleaks \
 && curl -sL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI}/nuclei_${NUCLEI}_linux_amd64.zip" -o nuclei.zip && unzip -o -q nuclei.zip nuclei \
 && curl -sL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA}/katana_${KATANA}_linux_amd64.zip" -o katana.zip && unzip -o -q katana.zip katana \
 && curl -sL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER}/subfinder_${SUBFINDER}_linux_amd64.zip" -o subfinder.zip && unzip -o -q subfinder.zip subfinder \
 && mv gitleaks nuclei katana subfinder /usr/local/bin/ && rm -f *.zip

# gh CLI (orgxray bruker gh api med GH_TOKEN)
ARG GH_VERSION=2.62.0
RUN curl -sL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz" | tar xz --strip-components=2 -C /usr/local/bin "gh_${GH_VERSION}_linux_amd64/bin/gh"

# orgxray KJÖRES ALDRI fra image — orgxray-sandbox bind-mounter
# ~/.local/bin/orgxray read-only over denne stien. En COPY'et versjon
# her ville bake inn en stille stale-kopi (funn fra utdatert
# detektor ser helt normalt ut). Shim gir klar melding i stedet.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'echo "[orgxray] mangler bind-mount — bruk orgxray-box/bin/orgxray-sandbox" >&2' \
    'exit 127' > /usr/local/bin/orgxray && chmod +x /usr/local/bin/orgxray

# nuclei-templates kreves for nuclei
RUN nuclei -update-templates -silent 2>/dev/null || true

RUN useradd -m -s /bin/bash pentester && mkdir -p /data && chown pentester:pentester /data
USER pentester

WORKDIR /data
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'reconbox klar. Verktøy: gitleaks nuclei katana subfinder nmap orgxray git jq python3'"]
