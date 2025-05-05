from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers

from users.models import User, Business, Organization


class OTPRequestSerializer(serializers.Serializer):
    to = serializers.CharField(max_length=10)


class OTPVerifySerializer(serializers.Serializer):
    to = serializers.CharField(max_length=10)
    otp = serializers.CharField(max_length=6)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'email', 'full_name', 'is_email_whatsapp_updates', 'is_email_verified',
            'is_notification', 'profile_pic', 'is_profile_complete', 'alternate_mobile_no',
        )
        read_only_fields = ('is_profile_complete',)

    def save(self, **kwargs):
        original_email = self.instance.email if self.instance else None

        user = super().save(**kwargs)

        new_email = self.validated_data.get('email', None)

        # Check if the email has changed
        if original_email and new_email and original_email != new_email:
            user.is_email_verified = False  # Reset the verification status
            user.save(update_fields=['is_email_verified'])  # Save only the changed field

        # Get all fields specified in the Meta class
        fields_to_check = self.Meta.fields

        # Check if all fields in Meta are present and non-empty in validated data
        is_complete = all(getattr(user, field) not in [None, ""] or field in ["profile_pic", "alternate_mobile_no"] for field in fields_to_check)

        # Set is_profile_complete based on the dynamic field check
        user.is_profile_complete = is_complete

        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        try:
            # Retrieve user by email
            user = User.objects.get(email=data.get('email'))
        except ObjectDoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        # Authenticate using mobile_no and password
        user = authenticate(mobile_no=user.mobile_no, password=data.get('password'))

        if user and user.is_active:
            return user
        raise serializers.ValidationError("Incorrect Credentials")


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'
        depth = 3


class BusinessSerializer(serializers.ModelSerializer):
    organization = Organization()

    class Meta:
        model = Business
        fields = '__all__'
        depth = 2


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'
        depth = 3
