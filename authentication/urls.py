from django.urls import path
from .views import RegisterView, LogoutAPIView, confirm_reset_pass,\
    update_user_details, driver_verified, update_user_image, driver_verification_list, reset_pass, SetNewPasswordAPIView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail, check_email, email_verification, resend_verification
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('logout/', LogoutAPIView.as_view(), name="logout"),
    path('email-verify/<str:email>/<str:token>/', email_verification, name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),
    path('check_email/<str:email>/', check_email, name="check-email"),
    path('resend/<str:email>/', resend_verification, name="resend-email"),
    path('update-details/', update_user_details, name="update-details"),
    path('update-image/', update_user_image, name="update-image"),
    path('request-password-reset/<email>/', reset_pass, name="request-password-reset"),
    path('confirm-reset-password/<email>/<str:token>/', confirm_reset_pass, name="request-password-reset"),
    path('author-verification/', driver_verification_list, name="author-verification"),
    path('author-verified/<str:username>/', driver_verified, name="author-verified"),
]
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
