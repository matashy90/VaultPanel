FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    VAULT_ADDR=http://host.docker.internal:8200
WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

RUN useradd --system --no-create-home dashboard
USER dashboard

EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/api/health')" || exit 1
CMD ["uvicorn", "main:app", "--app-dir", "app", "--host", "0.0.0.0", "--port", "8080"]
