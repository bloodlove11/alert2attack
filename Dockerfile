FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY datasets ./datasets

# Runtime + no dev. Do not --group train (CUDA/QLoRA is not this image).
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"
ENV ALERT2ATTACK_OLLAMA_BASE_URL=http://ollama:11434/v1
ENV ALERT2ATTACK_API_HOST=0.0.0.0
ENV ALERT2ATTACK_API_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "alert2attack.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
