FROM python:3.12-slim

WORKDIR /app

COPY honeypot.py .

RUN mkdir -p /app/logs

EXPOSE 2222

CMD ["python", "honeypot.py"]