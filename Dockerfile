FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TOOLBOX_DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN useradd --create-home --uid 10001 toolbox && mkdir -p /data && chown toolbox /data
USER toolbox
VOLUME ["/data"]
EXPOSE 8080

CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8080"]
