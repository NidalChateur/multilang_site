#!/usr/bin/env bash
# exit on error
set -o errexit

# Convert static asset files
poetry run python manage.py collectstatic --no-input

poetry run gunicorn multilang_site.wsgi:application



