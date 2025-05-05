import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sso.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.core.management import call_command

def create_superuser():
    UserModel = get_user_model()

    try:
        # Check if a superuser with the given mobile_no already exists
        if not UserModel.objects.filter(mobile_no='9999999999').exists():  # Set your desired mobile_no here
            # Use the `call_command` to create a superuser without input
            call_command('createsuperuser', '--noinput', mobile_no='9999999999')  # Update with the mobile_no

            # Fetch the newly created superuser
            user = UserModel.objects.get(mobile_no='9999999999')

            # Set the password
            user.set_password('1qaz2wsx3edc')

            # Customize fields for your User model
            user.full_name = 'Admin'
            user.is_staff = True
            user.is_superuser = True

            # Save the updates to the user
            user.save()
    except Exception as e:
        print(f"Error occurred while creating superuser: {e}")

if __name__ == '__main__':
    create_superuser()
