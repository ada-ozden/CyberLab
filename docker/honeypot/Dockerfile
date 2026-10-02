FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Run as an unprivileged user instead of root.
RUN useradd --create-home honeypot \
    && mkdir -p /app/logs \
    && chown -R honeypot:honeypot /app

COPY --chown=honeypot:honeypot honeypot.py .

USER honeypot

EXPOSE 2222

CMD ["python", "honeypot.py"]