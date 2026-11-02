# MeterGate v1.0.1 Zero-Config Open-Source Container Image (M-04, M-11, A1..A6, B1..B7, O1..O7)
FROM python:3.11-slim

LABEL org.opencontainers.image.title="MeterGate" \
      org.opencontainers.image.description="Open-Source AI Agent 3-Tier Firewall, Verifiable Cost Ledger & Standard MCP Middleware" \
      org.opencontainers.image.version="1.0.1" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    METERGATE_DB_PATH=/data/metergate.sqlite3 \
    METERGATE_POLICY_PATH=/config/default_policy.json

WORKDIR /app

COPY pyproject.toml LICENSE SECURITY.md README.md CHANGELOG.md version.json test_all.py ./
COPY src ./src
COPY docs ./docs
COPY tests ./tests
COPY .github ./.github

RUN pip install --no-cache-dir --no-deps -e . && \
    mkdir -p /data /config && \
    cp /app/src/metergate/config/default_policy.json /config/default_policy.json && \
    useradd -m -u 10001 metergate && \
    chown -R metergate:metergate /app /data /config

USER metergate
VOLUME ["/data", "/config"]
EXPOSE 8787

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD python3 -c "import urllib.request, sys; resp = urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=3); sys.exit(0 if resp.status == 200 else 1)"

ENTRYPOINT ["metergate"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8787"]
