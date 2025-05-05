from django.urls import path
from .views import SendOTPAPI, VerifyOTPAPI, UserDetailView, LoginAPI, verify_token_crud, VerifyEmailAccount, \
    SendVerificationEmailView

urlpatterns = [
    path('api/auth/send-otp/', SendOTPAPI.as_view(), name='send-otp'),
    path('api/auth/verify-otp/', VerifyOTPAPI.as_view(), name='verify-otp'),
    path('api/user/<int:pk>/', UserDetailView.as_view(), name='user-detail'),

    path('api/auth/login/', LoginAPI.as_view()),
    path('api/auth/user/crud/', verify_token_crud),

    path('api/send-verification-email/', SendVerificationEmailView.as_view(), name='send-verification-email'),
    path('api/activate/<uidb64>/<token>/', VerifyEmailAccount.as_view(), name='verify-email'),
]