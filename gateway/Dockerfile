# Build context is the repository root (see docker-compose.yml), so lab5/ can be shared.
FROM python:3.12-slim
WORKDIR /srv
COPY lab5/ lab5/
COPY gateway/ gateway/
EXPOSE 8080
CMD ["python", "gateway/gateway.py"]
