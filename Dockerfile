# GhostAP container (F073). Docker was not available where this was written: the file is
# checked by tests/test_deploy.py but has not been built. See docs/DEPLOY.md.
#
#   docker build -t ghostap .
#   docker run --rm -p 127.0.0.1:8050:8050 -e GHOSTAP_TOKEN=... ghostap      # synthetic demo replay
#   live capture: see docker-compose.yml (needs host networking and two capabilities)
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MPLCONFIGDIR=/tmp/matplotlib
RUN apt-get update \
 && apt-get install -y --no-install-recommends iw iproute2 libpcap0.8 openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY ghostap ghostap
COPY tools tools
COPY config.yaml evaluate.py ./
# the synthetic demo capture, outside the data volume so it is always there
RUN python tools/make_test_pcap.py >/dev/null && mkdir -p demo && mv data/test_capture.pcap data/test_labels.json demo/ \
 && useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin ghostap \
 && mkdir -p data && chown ghostap:ghostap data

USER ghostap
VOLUME ["/app/data"]
EXPOSE 8050
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-m", "ghostap.healthcheck", "8050"]
# Bound to all interfaces inside the container, so GhostAP turns token sign-in on.
ENTRYPOINT ["python", "-m", "ghostap.web", "--host", "0.0.0.0", "--port", "8050"]
CMD ["--pcap", "demo/test_capture.pcap"]
