#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements/prod_freeze.txt

# Convert static asset files
python manage.py collectstatic --no-input

# # Apply any outstanding database migrations
python manage.py migrate



