
from .views import RegistrationView, UsernameValidationView, EmailValidationView, LoginView, LogoutView, RequestPasswordResetEmail, CompletePasswordReset
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from . import views
from .views import *

urlpatterns = [
    path('register/', RegistrationView.as_view(), name="register"),
    path('login/', LoginView.as_view(), name="login"),
    path('logout/', LogoutView.as_view(), name="logout"),
    path('validate-username', csrf_exempt(UsernameValidationView.as_view()), name="validate-username"),
    path('validate-email', csrf_exempt(EmailValidationView.as_view()), name="validate-email"),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    # path('request-reset-link', csrf_exempt(RequestPasswordResetEmail.as_view()), name="request-password"),
    path('forget-password/' , RequestPasswordResetEmail.as_view(), name="forget_password"),
    path('set-new-password/<uidb64>/<token>/' , CompletePasswordReset.as_view(), name="change_password")
]

