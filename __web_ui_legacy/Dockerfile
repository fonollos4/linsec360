FROM python:3.13.5-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_ENV production

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ssh-client \
    git \
    ansible \
    sqlite3 && \
    apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create directories
RUN mkdir -p /app /ansible/inventory /var/log/linsec /root/.ssh

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Initialize database
RUN mkdir -p /app/instance && \
    sqlite3 /app/instance/linsec.db < schema.sql

# Expose the Flask port
EXPOSE 5000

# Start the application
CMD ["gunicorn", "app:app", "-b", "0.0.0.0:5000", "--workers", "4", "--access-logfile", "/var/log/linsec/access.log"]