# rag-search (clodia-platform#603): the RAG service next to the instance.
# Models are baked in at build time: at run time the container needs no
# internet, and no text leaves the host to compute an embedding.
FROM python:3.12-slim

ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 HF_HOME=/models TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1
WORKDIR /app
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install fastapi uvicorn "psycopg[binary]" pypdf sentence-transformers
RUN HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 python -c "from sentence_transformers import SentenceTransformer as S; S('paraphrase-multilingual-MiniLM-L12-v2'); S('intfloat/multilingual-e5-small')"
COPY ingest.py search_service.py ./
RUN useradd -r -u 10001 rag && chown -R rag /app
USER rag
EXPOSE 7900
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:7900/health',timeout=4).status==200 else 1)"
CMD ["uvicorn", "search_service:app", "--host", "0.0.0.0", "--port", "7900"]
