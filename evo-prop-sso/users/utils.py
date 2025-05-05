from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        # Include the user's email in the hash value for extra security
        return six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.email)


email_verification_token = EmailVerificationTokenGenerator()


def send_verification_email(request, user):
    # Generate a token that is specific to the user and their email
    token = email_verification_token.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

    # Construct the verification URL
    verification_url = request.build_absolute_uri(
        f"/activate/{uidb64}/{token}/"
    )

    # Send the email
    subject = 'Verify your email'
    message = render_to_string('email_verification.html', {
        'user': user,
        'verification_url': verification_url,
    })
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
