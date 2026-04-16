FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared/ /app/shared/

# Copy Alembic migration files
COPY alembic.ini /app/
COPY alembic/ /app/alembic/

# Copy service code
COPY app/ /app/app/

# Migration bootstrap script
COPY migrate.sh /app/migrate.sh
RUN chmod +x /app/migrate.sh

# Expose port
EXPOSE 8001

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
