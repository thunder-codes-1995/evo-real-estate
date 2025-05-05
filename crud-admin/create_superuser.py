# create_superuser.py
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'crud_admin.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.core.management import call_command

def create_superuser():
    UserModel = get_user_model()

    try:
        if not UserModel.objects.filter(username='admin').exists():
            call_command('createsuperuser', '--noinput', username='yogesh', email='yogesh@evoluxar.com')
            user = UserModel.objects.get(email='yogesh@evoluxar.com')
            user.set_password('1qaz2wsx3edc')  # Change to your desired password

            # Customize fields for NewUser model
            user.first_name = 'Admin'
            user.last_name = 'User'
            user.user_type = 'Admin'
            user.is_staff = True
            user.is_superuser = True

            user.save()
    except:
        pass
if __name__ == '__main__':
    create_superuser()
