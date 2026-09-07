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

.PHONY: test test-verbose test-one help

help:
	@echo "make test              tutta la suite"
	@echo "make test-verbose      idem, con il nome di ogni test"
	@echo "make test-one T=...    un modulo, una classe o un metodo"
	@echo "                       es. T=server.api.test_channels.SelfTagTests"

# `-t .` perché i test importano il package `server`: senza, la discovery li
# trova e poi non riesce a risolvere gli import relativi.
# Il venv serve: il gateway ha dipendenze runtime (httpx, mcp, cryptography).
#   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
test:
	$(PY) -m unittest discover -s server -t . -p "test_*.py"

test-verbose:
	$(PY) -m unittest discover -s server -t . -p "test_*.py" -v

test-one:
	@test -n "$(T)" || { echo "uso: make test-one T=server.api.test_channels"; exit 2; }
	$(PY) -m unittest $(T) -v
