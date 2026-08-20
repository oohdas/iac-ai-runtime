FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SEAN_OS_DATABASE=/data/sean-os.db

WORKDIR /app
COPY sean_os ./sean_os
COPY scripts ./scripts
RUN useradd --system --uid 10001 sean-os && mkdir -p /data && chown sean-os:sean-os /data
USER sean-os

CMD ["sh", "-c", "python scripts/worker.py --database \"$SEAN_OS_DATABASE\""]
