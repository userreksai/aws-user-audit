# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/userreksai/aws-user-audit" \
      org.opencontainers.image.title="AWS user operation audit" \
      org.opencontainers.image.description="Multi-account CloudTrail PDF email with a Beijing-time scheduler"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai \
    HOME=/root \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates fonts-wqy-zenhei tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && chmod 0755 /root
COPY requirements.txt /app/requirements.txt
RUN python -m venv /app/.venv \
    && /app/.venv/bin/python -m pip install -r /app/requirements.txt

# Explicit production allowlist: never COPY the checkout, credentials, or reports.
COPY aws_daily_audit.py aws_audit_multi.py audit_actions.py audit_alerts.py audit_config.py \
     audit_event_catalog.py audit_identity_summary.py audit_mail.py audit_mail_delivery.py \
     audit_mail_summary.py audit_pdf.py audit_resource_summary.py audit_schedule.py \
     audit_publication.py lark_notify.py aws-event-translations.json aws-audit-config.example.json /app/
COPY deploy/docker_runtime.py deploy/docker_config.py /app/deploy/

STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/app/.venv/bin/python", "/app/deploy/docker_runtime.py", "healthcheck", "--config", "/usr/local/aws-user-audit/aws-audit-config.json"]
ENTRYPOINT ["/app/.venv/bin/python", "/app/deploy/docker_runtime.py"]
CMD ["schedule", "--config", "/usr/local/aws-user-audit/aws-audit-config.json"]
