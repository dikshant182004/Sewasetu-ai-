FROM python:3.11-slim

# fonts-noto-core: Bengali/Assamese glyphs for the acknowledgment PDF.
# tzdata + localtime: the whole container (python, cron) runs on Indian Standard Time,
# the same clock the seed data, the scheme deadline and the application code use.
RUN apt-get update && apt-get install -y --no-install-recommends cron tzdata fonts-noto-core \
    && ln -sf /usr/share/zoneinfo/Asia/Kolkata /etc/localtime \
    && echo "Asia/Kolkata" > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/sewasetu/uploads /var/log/sewasetu \
    && crontab /app/deploy/crontab

EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "30", "app:app"]
