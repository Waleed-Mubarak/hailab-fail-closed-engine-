FROM python:3.11-slim

# Install core system security tools for zeroization & network containment
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy repository source code
COPY . /app

ENV PYTHONPATH=/app

# Execute Fail-Closed Engine by default
CMD ["python", "src/engine.py"]
