FROM python:3.11-slim

# Install core system security tools for zeroization & build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    coreutils \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy repository source code
COPY . .

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8501

# Execute the Flask Dashboard application
CMD ["python", "app.py"]
