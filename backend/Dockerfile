# Build context is the repository root (see docker-compose.yml), so lab5/ can be shared.
FROM python:3.12-slim
WORKDIR /srv
COPY lab5/ lab5/
COPY backend/ backend/
EXPOSE 9000
CMD ["python", "backend/sim.py"]
