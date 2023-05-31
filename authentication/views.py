
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from django.shortcuts import render, redirect
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
from validate_email import validate_email
from django.contrib import messages, auth
from django.core.mail import EmailMessage
from django.conf import settings
from .tokens import account_activation_token
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.template.loader import render_to_string
from django.contrib.auth import login, logout, authenticate, get_user_model
# from .helpers import send_forget_password_mail
from django.urls import reverse
import threading

class EmailThreading(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send(fail_silently=False)

def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()

        messages.success(request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('login')
    else:
        messages.error(request, "Activation link is invalid!")

    return redirect('authentication/register.html')




def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    message = render_to_string("authentication/template_activate_account.html", {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    })
    email = EmailMessage(mail_subject, message, to=[to_email])
    if email.send():
        messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
    else:
        messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')


class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']
        if not validate_email(email):
            return JsonResponse({'email_error': 'Email is invalid'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'sorry email is exists '}, status=409)
        return JsonResponse({'email_valid': True})
    

class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'username should only contain alphanumeric characters'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'sorry username is exists '}, status=409)
        return JsonResponse({'username_valid': True})

class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        # get user data
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'fieldValues': request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():

                if len(password) < 6:
                    messages.error(request, 'Password too short')
                    return render(request, 'authentication/register.html', context)
                
                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active = False
                user.save()
                activateEmail(request, user, email)
                return render(request, 'authentication/register.html')

        return render(request, 'authentication/register.html')


class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')
    
    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username=username, password=password)

            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, 'Welcome, ' +
                                     user.username+' you are now logged in')
                    return redirect('expenses')
                messages.error(
                    request, 'Account is not active,please check your email')
                return render(request, 'authentication/login.html')
            messages.error(
                request, 'Invalid credentials,try again')
            return render(request, 'authentication/login.html')

        messages.error(
            request, 'Please fill all fields')
        return render(request, 'authentication/login.html')
    


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'You have been logged out')
        return redirect('login')

import uuid

class RequestPasswordResetEmail(View):
    def get(self, request):
        return render(request, 'authentication/forget-password.html')
    def post(self, request):
        email = request.POST['email']

        context = {
            'values' : request.POST
        }

        if not validate_email(email):
            messages.error(request, 'Please supply a valid email')
            return render(request, 'authentication/forget-password.html', context)

        current_site = get_current_site(request)
        user = User.objects.filter(email = email)
        if user.exists():
            email_contents = {
                'user' : user[0],
                'domain' : current_site.domain,
                'uid' : urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token' : PasswordResetTokenGenerator().make_token(user[0]),
            }
        
            link = reverse("reset-user-password", kwargs = {
                'uidb64' : email_contents['uid'], 'token': email_contents['token']})

            email_subject = 'Password reset Instruction'
            reset_url = 'http://'+current_site.domain+link
            email = EmailMessage(
                email_subject,
                'Hi there, Please the link below to reset your password change',+reset_url,
                 'noreply@semycolon.com',
                 [email],
            )
            EmailThreading(email.start())


        messages.success(request, 'We have sent you an email to reset your password')
        return render(request, 'authentication/forget-password.html')
    








class CompletePasswordReset(View):
    def get(self, request, uidb64, token):
        return render(request, 'authentication/set-new-password.html')
    def post(self, request, uidb64, token):
        return render(request, 'authentication/set-new-password.html')