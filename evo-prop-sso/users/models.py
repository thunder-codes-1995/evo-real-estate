import os
from io import BytesIO

from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _
from django.core.files import File
from django.db import models
from storages.backends.s3boto3 import S3Boto3Storage
from PIL import Image
from rest_framework_simplejwt.tokens import RefreshToken

from users.manager import CustomAccountManager


class Organization(models.Model):
    name = models.CharField(max_length=155, unique=True, db_index=True)

    class Meta:
        verbose_name_plural = "Organization"

    def __str__(self):
        return self.name


class Business(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, null=False, blank=False, db_index=True)
    name = models.CharField(max_length=155, unique=True, db_index=True)
    logo = models.ImageField(default="pngegg.png", blank=True, null=True)
    business_code = models.CharField(max_length=156, unique=True, db_index=True)
    services_url = models.URLField(blank=True)
    services_websocket_url = models.CharField(max_length=200, blank=True)
    dynamic_services_url = models.URLField(blank=True)
    crud_admin_url = models.URLField(blank=True)
    ai_services_url = models.URLField(blank=True)
    ai_websocket_url = models.CharField(max_length=200, blank=True)

    class Meta:
        verbose_name_plural = "Business"

    def save(self, *args, **kwargs):
        self.business_code = (self.business_code).lower()
        obj = super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class User(AbstractUser):
    username = None
    first_name = None
    last_name = None

    mobile_no = models.CharField(max_length=11, unique=True)
    alternate_mobile_no = models.CharField(max_length=11, unique=True, null=True, blank=True)
    email = models.EmailField(_('email address'), unique=True, blank=True, null=True)
    full_name = models.CharField(max_length=50, blank=True, null=True)
    profile_pic = models.ImageField(upload_to='users/', blank=True, null=True, storage=S3Boto3Storage())

    is_profile_complete = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_mobile_no_verified = models.BooleanField(default=False)
    is_email_whatsapp_updates = models.BooleanField(default=False)
    is_notification = models.BooleanField(default=False)

    device_token = models.TextField(null=True, blank=True)

    otp = models.CharField(max_length=6, blank=True, null=True)

    business = models.ForeignKey(Business, on_delete=models.SET_NULL, null=True, blank=True)

    objects = CustomAccountManager()

    USERNAME_FIELD = 'mobile_no'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.mobile_no

    class Meta:
        verbose_name_plural = "Users"

    def reduce_image_size(self, image):
        split_tup = os.path.splitext(image.name)
        file_name = split_tup[0]
        file_extension = (split_tup[1]).replace('.', '')

        img = Image.open(image)
        thumb_io = BytesIO()

        image_format = img.format if img.format else 'JPEG'

        img.save(thumb_io, image_format, quality=70)
        new_image = File(thumb_io, name=image.name)
        return new_image

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
