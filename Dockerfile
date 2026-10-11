FROM python:3.12.13-slim-trixie AS build
WORKDIR /app
COPY pyproject.toml ./
COPY requirements.lock ./
COPY aegis ./aegis
RUN python -m venv /opt/venv && /opt/venv/bin/python -m pip install --no-cache-dir --upgrade pip==26.2.1 \
    && /opt/venv/bin/python -m pip install --no-cache-dir -c requirements.lock .

FROM python:3.12.13-slim-trixie
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 aegis && useradd --uid 10001 --gid aegis --create-home aegis
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
RUN /opt/venv/bin/python -m pip uninstall -y pip setuptools wheel \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/lib/python3.12/ensurepip
COPY --chown=aegis:aegis aegis ./aegis
COPY --chown=aegis:aegis migrations ./migrations
COPY --chown=aegis:aegis alembic.ini ./
COPY --chown=aegis:aegis scripts ./scripts
USER aegis
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/system/liveness', timeout=3)"
CMD ["uvicorn", "aegis.api:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-access-log"]
