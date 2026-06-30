FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY data /app/data
COPY sources /app/sources
COPY tools /app/tools

# Bake the knowledge corpus during the build so the AI is RAG-augmented with it
# at runtime. The repository owner has signed off on mirroring the full text of
# entries flagged "fullText": true (HackTricks / PayloadsAllTheThings), so
# ALLOW_FULL_TEXT defaults to "true": the build fetches and mirrors those bodies
# (requires build-time network access to the source sites). Set
# ALLOW_FULL_TEXT=false for a hermetic, network-free build that regenerates
# data/corpus.json from the curated notes only.
ARG ALLOW_FULL_TEXT=true
ARG EXPAND_IMPORTS=true
RUN IMPORT_ARGS=""; \
    if [ "$EXPAND_IMPORTS" = "true" ]; then IMPORT_ARGS="--expand-imports"; fi; \
    if [ "$ALLOW_FULL_TEXT" = "true" ]; then \
        python3 tools/generate_corpus.py fetch-web-text \
            --sources sources/corpus_sources.json \
            --output data/website_text.json \
            $IMPORT_ARGS && \
        python3 tools/generate_corpus.py build \
            --sources sources/corpus_sources.json \
            --output data/corpus.json \
            --review-output data/corpus.review.json \
            --website-text data/website_text.json \
            $IMPORT_ARGS \
            --allow-full-text ; \
    else \
        python3 tools/generate_corpus.py build \
            --sources sources/corpus_sources.json \
            --output data/corpus.json \
            --review-output data/corpus.review.json \
            $IMPORT_ARGS \
            --no-full-text ; \
    fi

EXPOSE 8092

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8092"]
