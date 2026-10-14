# Smart Cloud Shield — Production Dockerfile
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=5000

WORKDIR /app

# Install build dependencies for high-performance C-extensions & OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libgomp1 \
    tesseract-ocr \
    tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies including gunicorn for production
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application source code
COPY . .

# Seed initial database, default users, sample files and train ML model
RUN python seed.py

EXPOSE 5000

# Run with 2 Gunicorn worker processes
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
