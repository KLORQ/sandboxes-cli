# Kimi Code CLI agent image, pinned for reproducible local sandboxes.
FROM python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c

RUN pip install --no-cache-dir kimi-cli==0.43

# The sandbox runtime supplies the workspace and agent arguments.
ENTRYPOINT ["kimi"]
