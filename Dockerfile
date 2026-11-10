FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m meridian
WORKDIR /app
COPY server.py index.html ./
USER meridian
ENV MERIDIAN_PORT=8765
EXPOSE 8765
# Meridian only listens on 127.0.0.1 (by design), so run the container with --net=host (Linux):
#   docker run --rm --net=host meridian     ->  http://127.0.0.1:8765
CMD ["python3", "server.py", "--serve"]
