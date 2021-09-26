import os
import requests

from django.contrib.auth.decorators import login_required
from django.contrib import auth, messages
from django.shortcuts import render, redirect, reverse
from django.views.generic import FormView, DetailView, UpdateView
from django.contrib.auth import authenticate, login, logout
from django.db.utils import IntegrityError
from django.urls import reverse_lazy
from .models import User
from . import mixins, forms
from .exception import (
    LoggedOutOnlyFunctionView,
    KakaoException,
    NaverException,
)


class SignUpView(mixins.LoggedOutOnlyView, FormView):
    
    """ Sign Up View """

    form_class = forms.SignUpForm
    success_url = reverse_lazy("user:check-email")
    template_name = "signup.html"

    def form_valid(self, form):
        try:
            form.save()
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            user = authenticate(self.request, username=email, password=password)
            user.verify_email()
            return super().form_valid(form)
        except IntegrityError:
            return redirect(reverse("user:signup"))


class LoginView(FormView):

    """ Login View """

    form_class = forms.LoginForm
    success_url = reverse_lazy("home")
    template_name = "login.html"

    def form_valid(self, form):
        email = form.cleaned_data.get("email")
        password = form.cleaned_data.get("password")
        user = authenticate(self.request, username=email, password=password)
        print(email, password, user, user.email_verified)
        if user is not None and user.email_verified is True:
            messages.success(self.request, f"{user.first_name} logged in")
            login(self.request, user)
        else:
            return redirect(reverse("user:login"))
        return super().form_valid(form)


def check_email(request):
    return render(request, "email/check_email.html")

def kakao_login(request):
    try:
        if request.user.is_authenticated:
            raise LoggedOutOnlyFunctionView("User already logged in")
        client_id = os.environ.get("KAKAO_ID")
        redirect_uri = "http://chungsol.pythonanywhere.com/auth/login/kakao/callback/"

        return redirect(
            f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
        )
    except KakaoException as error:
        messages.error(request, error)
        return redirect("home")
    except LoggedOutOnlyFunctionView as error:
        messages.error(request, error)
        return redirect("home")

def kakao_login_callback(request):
    try:
        if request.user.is_authenticated:
            print("User already logged in")
            raise LoggedOutOnlyFunctionView("User already logged in")
        code = request.GET.get("code", None)
        if code is None:
            print("Can't get code")
            KakaoException("Can't get code")
        client_id = os.environ.get("KAKAO_ID")
        redirect_uri = "http://chungsol.pythonanywhere.com/auth/login/kakao/callback/"
        client_secret = os.environ.get("KAKAO_SECRET")
        request_access_token = requests.post(
            f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}&client_secret={client_secret}",
            headers={"Accept": "application/json"},
        )
        access_token_json = request_access_token.json()
        error = access_token_json.get("error", None)
        if error is not None:
            print(error)
            KakaoException("Can't get access token")
        access_token = access_token_json.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_request = requests.post(
            "https://kapi.kakao.com/v2/user/me",
            headers=headers,
        )
        profile_json = profile_request.json()
        kakao_account = profile_json.get("kakao_account")
        profile = kakao_account.get("profile")

        nickname = profile.get("nickname", None)
        email = kakao_account.get("email", None)
        gender = kakao_account.get("gender", None)
        if not email or email == "":
            print("email required")
            raise KakaoException("Email required")

        user = User.objects.get_or_none(email=email)
        if user is not None:
            if user.login_method != User.LOGIN_KAKAO:
                raise KakaoException(f"Please login with {user.login_method}")
        else:
            user = User.objects.create_user(
                email=email,
                username=nickname,
                login_method=User.LOGIN_KAKAO,
            )

            user.set_unusable_password()
            user.save()
        messages.success(request, f"{user.email} signed up and logged in with Kakao")
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return redirect(reverse("home"))
    except KakaoException as error:
        messages.error(request, error)
        return redirect(reverse("home"))
    except LoggedOutOnlyFunctionView as error:
        messages.error(request, error)
        return redirect(reverse("home"))

def naver_login_callback(request):
    try:
        if request.user.is_authenticated:
            print("User already logged in")
            raise LoggedOutOnlyFunctionView("User already logged in")
        csrf_token = request.GET.get('state')
        code = request.GET.get('code')

        client_id = os.environ.get("KAKAO_ID")
        redirect_uri = "http://chungsol.pythonanywhere.com/auth/login/kakao/callback/"
        client_secret = os.environ.get("KAKAO_SECRET")
        request_access_token = requests.post(
            f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}&client_secret={client_secret}",
            headers={"Accept": "application/json"},
        )
        access_token_json = request_access_token.json()
        error = access_token_json.get("error", None)
        if error is not None:
            print(error)
            KakaoException("Can't get access token")
        access_token = access_token_json.get("access_token")
        headers = {"Authorization": f"Bearer {access_token}"}
        profile_request = requests.post(
            "https://kapi.kakao.com/v2/user/me",
            headers=headers,
        )
        profile_json = profile_request.json()
        kakao_account = profile_json.get("kakao_account")
        profile = kakao_account.get("profile")

        nickname = profile.get("nickname", None)
        email = kakao_account.get("email", None)
        gender = kakao_account.get("gender", None)
        if not email or email == "":
            print("email required")
            raise KakaoException("Email required")

        user = User.objects.get_or_none(email=email)
        if user is not None:
            if user.login_method != User.LOGIN_KAKAO:
                raise NaverException(f"Please login with {user.login_method}")
        else:
            user = User.objects.create_user(
                email=email,
                username=nickname,
                login_method=User.LOGIN_KAKAO,
            )

            user.set_unusable_password()
            user.save()
        messages.success(request, f"{user.email} signed up and logged in with Kakao")
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        return redirect(reverse("home"))
    except NaverException as error:
        messages.error(request, error)
        return redirect(reverse("home"))
    except LoggedOutOnlyFunctionView as error:
        messages.error(request, error)
        return redirect(reverse("home"))

def complete_verification(request, key):
    try:
        if request.user.is_authenticated:
            raise LoggedOutOnlyFunctionView("Please verify email first")
        user = User.objects.get_or_none(email_secret=key)
        if user is None:
            messages.error(request, "User does not exist")
            return redirect(reverse("home"))
        user.email_verified = True
        user.email_secret = ""
        user.save()
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        messages.success(request, f"{user.email} verification is completed")
        return redirect(reverse("home"))
    except LoggedOutOnlyFunctionView as error:
        messages.error(request, error)
        return redirect("home")

@login_required
def log_out(request):
    logout(request)
    return redirect(reverse("home"))
