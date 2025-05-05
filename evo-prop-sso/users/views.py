from django.contrib.auth import login
from django.core.mail import send_mail, EmailMultiAlternatives
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.template.loader import render_to_string
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from rest_framework.generics import RetrieveUpdateAPIView, GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import random
import requests
import smtplib
from email.message import EmailMessage
from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from urllib3 import request

from .serializers import OTPRequestSerializer, OTPVerifySerializer, UserSerializer, LoginSerializer, BusinessSerializer
from .models import User, Business
from .utils import email_verification_token


class SendOTPAPI(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            to_number = data.get('to')

            otp = str(random.randint(1000, 9999))
            user = User.objects.filter(mobile_no=to_number, is_active=True).first()

            if not user:
                # Create a new user if mobile_no not present
                user = User.objects.create(
                    mobile_no=to_number,
                    is_active=True,  # Set is_active=True for active users
                    otp=otp,  # Optionally store the OTP in the user model
                )
                user.set_unusable_password()  # No password for OTP-based login
                user.save()

            # Try sending email if the user has an email address
            if user.email:
                try:
                    to_email = user.email
                    subject = "Evoluxar Login OTP"
                    content = f"{otp} is your OTP to login and access the app - ELEGANCE."
                    message = EmailMessage()
                    message.set_content(content)
                    message["Subject"] = subject
                    message["From"] = "codeofgrowthtechnologies@gmail.com"
                    message["To"] = to_email

                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login("codeofgrowthtechnologies@gmail.com", "jldrrjgkbxxnssyh")
                        server.send_message(message)
                except Exception as e:
                    print(f"Email send failed: {e}")
                    pass

            KALEYRA_API_KEY = settings.KALEYRA_API_KEY
            KALEYR_SID = settings.KALEYR_SID

            url = f"https://api.kaleyra.io/v1/{KALEYR_SID}/messages"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "api-key": KALEYRA_API_KEY,
            }

            if to_number:
                user.otp = otp
                user.save()
                data = {
                    "to": f"+91{to_number}",
                    "type": "OTP",
                    "sender": "ELEANC",
                    "body": f"{otp} is your OTP to login and access the app - ELEGANCE.",
                    "template_id": "1707170071594360463",
                }

                try:
                    response = requests.post(url, headers=headers, data=data)
                    if response.status_code // 100 == 2:
                        if to_number != '7777788888':
                            user.otp = otp
                            user.save()
                        return Response({"status": "success", "message": "OTP sent successfully"},
                                        status=status.HTTP_200_OK)
                    else:
                        if to_number != '7777788888':
                            user.otp = otp
                            user.save()
                        return Response({"status": "error", "message": "Failed to send OTP"},
                                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                except Exception as e:
                    return Response({"status": "error", "message": f"Failed to send OTP: {str(e)}"},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                return Response({"message": "Please send a valid mobile number"},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPAPI(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validated_data
            to_number = data.get('to')
            entered_otp = data.get('otp')

            user = User.objects.filter(mobile_no__iexact=to_number, is_active=True).first()
            if user:
                if user.otp == entered_otp:
                    # Set mobile number verification to true
                    user.is_mobile_no_verified = True

                    # Clear OTP after verification
                    user.otp = None
                    user.save()

                    # Prepare user data
                    user_data = {
                        "id": user.id,
                        "email": user.email,
                        "full_name": user.full_name,
                        "mobile_no": user.mobile_no,
                        "alternate_mobile_no": user.alternate_mobile_no,
                        "is_active": user.is_active,
                        "is_email_verified": user.is_email_verified,
                        "is_profile_complete": user.is_profile_complete,
                        "profile_pic": str(user.profile_pic.url) if user.profile_pic else '',
                        # Add any additional fields you need
                    }

                    res = {
                        "message": "success",
                        "result": {
                            "user": user_data,
                            "token": user.tokens()
                        }
                    }
                    return Response(res, status=status.HTTP_200_OK)
                else:
                    return Response({"status": "error", "message": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"status": "error", "message": "User does not exist"},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserDetailView(RetrieveUpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_response(self):
        user = User.objects.get(id=self.request.user.id)
        user_data = {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "mobile_no": user.mobile_no,
            "alternate_mobile_no": user.alternate_mobile_no,
            "is_active": user.is_active,
            "is_profile_complete": user.is_profile_complete,
            "is_email_verified": user.is_email_verified,
            "profile_pic": str(user.profile_pic.url) if user.profile_pic else '',
            # Add any additional fields you need
        }

        res = {
            "message": "success",
            "result": {
                "user": user_data,
                "token": user.tokens()
            }
        }
        return Response(res, status=status.HTTP_200_OK)

    def get(self, request, *args, **kwargs):
        response = self.retrieve(request, *args, **kwargs)
        if response.status_code == 200:
            return self.get_response()
        else:
            return response

    def put(self, request, *args, **kwargs):
        response = self.update(request, *args, **kwargs)
        if response.status_code == 200:
            return self.get_response()
        else:
            return response

    def patch(self, request, *args, **kwargs):
        response = self.partial_update(request, *args, **kwargs)
        if response.status_code == 200:
            return self.get_response()
        else:
            return response


class LoginAPI(GenericAPIView):
    serializer_class = LoginSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data

            if user.is_superuser or user.is_system_user:
                business = Business.objects.filter(id=user.business.id).first()
                res = {
                    "message": "success",
                    "result": {
                        "user": UserSerializer(instance=user).data,
                        "token": user.tokens(),
                        "response_biz": BusinessSerializer(business, context=self.get_serializer_context()).data,

                    }
                }
                return Response(res, status=status.HTTP_200_OK)

            else:
                data = {"message": "Unauthorized", "result": {}}
                return Response({'result': data}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            res = {
                "message": serializer.errors,
                "result": {}
            }
            return Response(res, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
# For CRUD Admin Token Verification
def verify_token_crud(request):
    # try:
    # Check if the Authorization header exists in the request
    if 'HTTP_AUTHORIZATION' in request.META:
        # Get client's IP address
        # client_ip = request.META.get('REMOTE_ADDR')
        authorization_header = request.META['HTTP_AUTHORIZATION']
        # Now you can work with the authorization header
        # For example, you can check if it starts with 'Bearer' for JWTs
        if authorization_header.startswith('Bearer '):
            jwt_token = authorization_header[7:]  # Remove 'Bearer ' prefix
            jwt_object = JWTAuthentication()
            header = jwt_object.get_header(request)
            raw_token = jwt_object.get_raw_token(header)
            validated_token = jwt_object.get_validated_token(raw_token)
            user = jwt_object.get_user(validated_token)

            if user:
                business = user.business
                business_data = BusinessSerializer(instance=business).data

                res = {
                    "message": "success",
                    "result": {
                        "user_id": user.id,
                        "first_name": user.first_name,
                        "business": business_data
                    },
                }
            else:
                res = {}
            return JsonResponse(res, status=200)
        else:
            # Handle other types of authorization headers here
            return HttpResponse('Unsupported Authorization method')
    else:
        # Authorization header is not present in the request
        return HttpResponse('No Authorization header found', status=401)  # Unauthorized


class SendVerificationEmailView(APIView):
    def get(self, request):
        try:
            user = request.user

            if user.is_email_verified:
                return Response({
                    'error': 'This account email is already verified.'
                }, status=status.HTTP_400_BAD_REQUEST)

            if not user.email:
                return Response({
                    'error': 'No email address in profile.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Generate the token and encode the user ID
            token = email_verification_token.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

            # Create the email verification URL
            verification_url = request.build_absolute_uri(f'/api/activate/{uidb64}/{token}/')

            # Render the HTML message
            subject = 'Verify your email'
            message = render_to_string('users/email_verification.html', {
                'user': user,
                'verification_url': verification_url,
            })

            # Use EmailMultiAlternatives for sending HTML emails
            email_message = EmailMultiAlternatives(
                subject=subject,
                body=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email]
            )
            email_message.attach_alternative(message, "text/html")
            email_message.send()

            return Response({
                'message': 'Verification email sent. Please check your inbox.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'error': 'User with this email does not exist.'
            }, status=status.HTTP_404_NOT_FOUND)


class VerifyEmailAccount(APIView):
    def get(self, request, uidb64, token, format=None):
        try:
            # Decode the user ID from the URL
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        # Check if the token is valid and the user is not already active
        if user is not None and email_verification_token.check_token(user, token):
            user.is_email_verified = True  # Activate the user's account

            fields_to_check = (
                'email', 'full_name', 'is_email_whatsapp_updates',
                'is_notification', 'profile_pic', 'is_profile_complete', 'alternate_mobile_no',
            )
            # Check if all fields in Meta are present and non-empty in validated data
            is_complete = all(
                getattr(user, field) not in [None, ""] or field in ["profile_pic", "alternate_mobile_no"] for field in
                fields_to_check)
            # Set is_profile_complete based on the dynamic field check
            user.is_profile_complete = is_complete
            user.save()

            return Response({
                'message': 'Your email has been verified successfully!'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Activation link is invalid or expired.'
            }, status=status.HTTP_400_BAD_REQUEST)

