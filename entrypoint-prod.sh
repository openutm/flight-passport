#!/bin/bash

source .venv/bin/activate

echo Waiting for DBs...
if ! wait-for-it --service ${POSTGRES_HOST:-db-passport}:${POSTGRES_PORT:-5432}; then
    exit
fi

# Apply database migrations
echo "Apply database migrations"
python manage.py migrate --noinput

echo "Setting site name"
python manage.py initialize_db

echo "Creating superuser"
python manage.py init_admin

# echo "Collecting static"
# python manage.py collectstatic --noinput

# Start server
echo "Starting server.."
gunicorn --bind :9000 --workers 3 flight_passport.wsgi
