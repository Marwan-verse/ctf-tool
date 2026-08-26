# syntax=docker/dockerfile:1.7

FROM python:3.12.11-slim-bookworm

ARG ZSTEG_VERSION=0.2.13

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    FORENSCOPE_DATA_DIR=/data \
    FORENSCOPE_DB_PATH=/data/forenscope.sqlite3 \
    FORENSCOPE_ALLOWED_HOSTS=localhost,127.0.0.1,[::1],backend \
    MAGICK_MEMORY_LIMIT=256MiB \
    MAGICK_MAP_LIMIT=512MiB \
    MAGICK_DISK_LIMIT=1GiB \
    MAGICK_TIME_LIMIT=60 \
    MAGICK_WIDTH_LIMIT=32KP \
    MAGICK_HEIGHT_LIMIT=32KP

# These are analysis helpers, not trusted parsers. The API still invokes them
# with argument arrays, timeouts, output quotas, and a per-job working tree.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        file \
        gifsicle \
        imagemagick \
        libimage-exiftool-perl \
        libjpeg-turbo-progs \
        libmagic1 \
        libtiff-tools \
        p7zip-full \
        pngcheck \
        ruby \
        steghide \
        tesseract-ocr \
        tini \
        webp \
        zbar-tools \
    && gem install --no-document zsteg --version "${ZSTEG_VERSION}" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/*

WORKDIR /opt/forenscope

COPY pyproject.toml ./
COPY app ./app

RUN python -m pip install . \
    && groupadd --gid 10001 forenscope \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin forenscope \
    && mkdir -p /data/jobs /data/tmp \
    && chown -R forenscope:forenscope /data /opt/forenscope

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=4s --start-period=15s --retries=4 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).read()"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
