# clodia-tools — gateway MCP HTTP autosufficiente (reference monitor della colonia).
# Immagine indipendente dall'agent-server: nessuna dipendenza dal tree clodia-logic.
FROM python:3.12-slim

WORKDIR /app

# Node.js + npx: necessari per montare MCP server "stdio" distribuiti via npm
# (es. `npx @pkg@latest`). Layer precoce (cambia raramente) per la cache.
# NB: `npx <pkg>` scarica ed esegue codice da npm a runtime → pinnare le versioni
# e vettare i pacchetti (rischio supply-chain). Egress npm richiesto a runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Deps prima del codice per sfruttare la cache dei layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Config via env (override del workspace_root Mac in config.yaml):
#   CLODIA_CA_CRT, CLODIA_PKI_CERTS, CLODIA_PKI_REVOKED, CLODIA_WORKSPACE_ROOT
# I secret (CA, cert pubblici, creds trello/email) sono MONTATI a runtime,
# mai dentro l'immagine.
EXPOSE 7849

CMD ["python3", "cli.py", "--http", "--port", "7849"]
