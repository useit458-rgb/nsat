# Network Security Assessment Toolkit (NSAT) Dockerfile
FROM python:3.11-slim

# Prevent python from writing pyc files to disk and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies: nmap, lynis, build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    lynis \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency specifications and install
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Ensure instance and reports directories exist
RUN mkdir -p instance reports/generated

# Expose default port
EXPOSE 5000

# Default non-root user setup for defensive container execution
RUN useradd -m -u 1000 nsatuser && \
    chown -R nsatuser:nsatuser /app
USER nsatuser

# Run WSGI application
CMD ["python", "wsgi.py"]
