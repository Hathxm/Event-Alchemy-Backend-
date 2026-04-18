FROM python:3.11-slim

# Install system dependencies:
# - libpq5: PostgreSQL client runtime library (required by psycopg2)
# - libpq-dev: headers needed to compile psycopg2 from source
# - build-essential: gcc and other tools for compiling C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libpq-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies before copying the full source
# so Docker can cache this layer when only app code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

EXPOSE 8000

# Use daphne as the ASGI server — the app uses Django Channels
# (ASGI_APPLICATION is set in settings.py; daphne is in INSTALLED_APPS)
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "backend.asgi:application"]
