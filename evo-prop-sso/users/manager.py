from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _


class CustomAccountManager(BaseUserManager):

    def create_superuser(self, mobile_no, password, **other_fields):
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if other_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(mobile_no, password, **other_fields)

    def create_user(self, mobile_no, password=None, **other_fields):
        if not mobile_no:
            raise ValueError(_('The mobile number must be set'))

        other_fields.setdefault('is_active', True)

        user = self.model(mobile_no=mobile_no, **other_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
