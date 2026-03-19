FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY dashboard/requirements.txt /tmp/dashboard-requirements.txt
RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install -r /tmp/dashboard-requirements.txt

COPY . /app

EXPOSE 8787

CMD ["uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", "8787"]
