from django.urls import path
from . import views

app_name = "user"

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="signup"),
    path("email/check/", views.check_email, name="check-email"),
    path("login/", views.LoginView.as_view(), name="login"),

    path("login/kakao/", views.kakao_login, name="kakao-login"),
    path(
        "login/kakao/callback/",
        views.kakao_login_callback,
        name="kakao-callback",
    ),

    path(
        "login/<provider>/callback/",
        views.SocialLoginCallbackView.as_view(),
    ),
    path(
        "verify/<str:key>/",
        views.complete_verification,
        name="complete-verification",
    ),
    path("logout/", views.log_out, name="logout"),
]
