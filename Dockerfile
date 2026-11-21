FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m meridian
WORKDIR /app
COPY server.py ai.py index.html ./
COPY locales ./locales
COPY assets ./assets
USER meridian
ENV MERIDIAN_PORT=8765 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8765
# Meridian only listens on 127.0.0.1 (by design), so run the container with --net=host (Linux):
#   docker run --rm --net=host meridian     ->  open the link printed in the log (http://127.0.0.1:8765/?k=...; it works once)
#   (add  -e MERIDIAN_LANG=tr  for another language). The app files are owned by root and read-only for the unprivileged "meridian" user.
# Docker Desktop on Windows/macOS runs containers inside a VM, so it cannot scan your real LAN: install Meridian natively there (install.py).
CMD ["python3", "server.py", "--serve"]
