FROM docker:29-cli AS dockercli
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates libstdc++6 libgcc-s1 git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt uv==0.13.7
COPY engine /opt/strix-engine
ENV LITELLM_LOCAL_MODEL_COST_MAP=True TIKTOKEN_CACHE_DIR=/opt/tokenizer-cache UV_PYTHON_DOWNLOADS=never
RUN cd /opt/strix-engine && uv sync --frozen --no-dev --python /usr/local/bin/python3
# Cache the engine's existing tokenizer data for offline context management.
RUN /opt/strix-engine/.venv/bin/python -c "import tiktoken; tiktoken.get_encoding('cl100k_base'); tiktoken.get_encoding('o200k_base')" && uv cache clean
COPY task_submission.py task_reuse.py greybox.py service.py worker.py portal.py runtime_config.py launcher.py entrypoint.sh model_calls.py call_details.py engine_bootstrap.py ./
COPY static ./static
COPY strix-launcher.sh /usr/local/bin/strix
COPY STRIX-LICENSE /usr/share/licenses/strix/LICENSE
RUN chmod 755 /app/entrypoint.sh /usr/local/bin/strix
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 STRIX_DATA_DIR=/srv/strix-data
ENV STRIX_DOCKER_SANDBOX_NETWORK=bridge
EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["all"]
