FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY data /app/data
COPY sources /app/sources
COPY tools /app/tools

# Bake the knowledge corpus during the build so the AI is RAG-augmented with it
# at runtime. By default this regenerates data/corpus.json from the curated
# sources (hermetic, no network). Set ALLOW_FULL_TEXT=true to additionally fetch
# and mirror the full text of entries flagged "fullText": true (HackTricks /
# PayloadsAllTheThings) — this is an explicit sign-off and requires build-time
# network access to the source sites.
ARG ALLOW_FULL_TEXT=false
RUN if [ "$ALLOW_FULL_TEXT" = "true" ]; then \
        python3 tools/generate_corpus.py fetch-web-text \
            --sources sources/corpus_sources.json \
            --output data/website_text.json && \
        python3 tools/generate_corpus.py build \
            --sources sources/corpus_sources.json \
            --output data/corpus.json \
            --review-output data/corpus.review.json \
            --website-text data/website_text.json \
            --allow-full-text ; \
    else \
        python3 tools/generate_corpus.py build \
            --sources sources/corpus_sources.json \
            --output data/corpus.json \
            --review-output data/corpus.review.json ; \
    fi

EXPOSE 8092

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8092"]
