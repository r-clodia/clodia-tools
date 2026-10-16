# Comandi di verifica. `make test` è il solo modo in cui questa suite va
# eseguita, così il comando vive nel repository invece che nella memoria di chi
# l'ha lanciato l'ultima volta (decision record 34).
PY ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

# NESSUN agent-server vero durante i test: porta 9 (discard). Da quando l'annuncio
# di un messaggio appartiene all'atto di postare (clodia-platform#219),
# `TopicService.post_message` chiama l'agent-server a ogni post — e i test lo
# chiamano centinaia di volte. Il default nel codice è un host della colonia:
# su un runner non risolve, ma su una macchina della colonia SÌ, e la suite
# dipingerebbe bolle nei topic veri. È la stessa garanzia scritta che il
# workflow dà già a `CLODIA_TOOLS_MCP_URL`, spostata dove vale anche in locale.
export AGENT_SERVER_URL ?= http://127.0.0.1:9

# Niente di ciò che la suite tocca sta nella datadir VERA della colonia.
#
# Il 14 ott 2026 una run della suite dentro lo scratch di un agente ha migrato
# tre file di stato del gateway fuori da `/datadir` rinominando gli originali
# (clodia-platform#541, #545 §6): `CLODIA_TOOLS_STATE_DIR` puntava a una temp
# dir e `CLODIA_DATA` era ancora `/datadir`, perché in ogni scratch di agente
# quella variabile È già impostata sulla datadir vera.
#
# Per questo `:=` e non `?=`: `?=` eredita esattamente il valore che ha causato
# l'incidente, quindi non sarebbe isolamento ma una speranza. Qui la suite non
# ha alcun motivo di leggere o scrivere lo stato dell'istanza: per i test che
# un percorso vivo lo vogliono, c'è una temp dir per test.
TEST_AUDIT := $(shell mktemp -d 2>/dev/null || echo /tmp/clodia-tools-test-audit)
TEST_SANDBOX := $(shell mktemp -d 2>/dev/null || echo /tmp/clodia-tools-test-sandbox)
export CLODIA_AUDIT_DIR := $(TEST_AUDIT)/store
export CLODIA_AUDIT_KEY_DIR := $(TEST_AUDIT)/key
export CLODIA_DATA := $(TEST_SANDBOX)/data
export CLODIA_TOOLS_STATE_DIR := $(TEST_SANDBOX)/state
export CLODIA_TOPICS_ROOT := $(TEST_SANDBOX)/topics
export CLODIA_SPAWNS_ROOT := $(TEST_SANDBOX)/spawns
export CLODIA_SECRETS_DIR := $(TEST_SANDBOX)/secrets
export CLODIA_PKI_CERTS := $(TEST_SANDBOX)/pki/certs
export CLODIA_PKI_REVOKED := $(TEST_SANDBOX)/pki/revoked.json
export CLODIA_VAULT_DIR := $(TEST_SANDBOX)/vault

.PHONY: test test-verbose test-one version-check help

help:
	@echo "make test              tutta la suite (e il controllo di versione, in CI)"
	@echo "make test-verbose      idem, con il nome di ogni test"
	@echo "make test-one T=...    un modulo, una classe o un metodo"
	@echo "                       es. T=server.api.test_channels.SelfTagTests"
	@echo "make version-check     __version__ > quella del branch di destinazione"

# `__version__` deve essere più alto di quello che il branch di destinazione ha
# ADESSO, non di quello da cui il branch è partito: è nell'intervallo fra i due
# che entra l'altra PR con lo stesso numero, e al merge git non segnala nulla
# perché la riga di arrivo è identica. È successo il 27 set 2026 fra la #317 e
# la #318, entrambe su `2.36.0` (clodia-platform#415, #416, #355).
#
# Sta qui e non in un `.github/workflows/version.yml` perché la credenziale con
# cui gli agenti pubblicano non ha lo scope `workflow` e il remoto rifiuta ogni
# push sotto `.github/` (decisione dell'owner, 23 ago 2026 — commit d57e690 di
# questo repository). `make test` è ciò che la CI esegue, quindi è l'unico punto
# agganciabile da questo lato — ed è anche il motivo per cui il controllo è un
# PREREQUISITO di `test`: agganciato altrove tornerebbe a essere codice di
# guardia che nessuna macchina invoca.
#
# `GITHUB_BASE_REF` è valorizzato solo nelle run di `pull_request`. Fuori di lì
# non si confronta niente: in locale non c'è un bersaglio, e su un push a `main`
# il confronto sarebbe `main` contro sé stesso, cioè rosso sempre.
version-check:
	@if [ -z "$(GITHUB_BASE_REF)" ]; then \
	  echo "version-check: fuori da una pull request, niente con cui confrontare"; \
	else \
	  $(PY) -m server.version_guard --base-ref "$(GITHUB_BASE_REF)"; \
	fi

# `-t .` perché i test importano il package `server`: senza, la discovery li
# trova e poi non riesce a risolvere gli import relativi.
# Il venv serve: il gateway ha dipendenze runtime (httpx, mcp, cryptography).
#   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
test: version-check
	$(PY) -m unittest discover -s server -t . -p "test_*.py"

test-verbose:
	$(PY) -m unittest discover -s server -t . -p "test_*.py" -v

test-one:
	@test -n "$(T)" || { echo "uso: make test-one T=server.api.test_channels"; exit 2; }
	$(PY) -m unittest $(T) -v
