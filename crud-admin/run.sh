#!/bin/sh

cd /var/www/html/crud-admin/
#source venv/bin/activate

pip install -r requirements.txt
python manage.py makemigrations
python manage.py makemigrations crud_app

python manage.py migrate

python manage.py createsuperuser

