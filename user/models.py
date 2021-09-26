import uuid
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import UserManager, AbstractUser
from django.core.mail import send_mail
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from chungsol.settings import EMAIL_FROM


class CustomUserModelManager(UserManager):
    def get_or_none(self, **kwargs):
        try:
            return self.get(**kwargs)
        except self.model.DoesNotExist:
            return None

class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, username, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.username = username
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, username=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    email = models.EmailField(verbose_name=_('email address'), unique=True, blank=False)
    username = models.CharField(_('username'), max_length=30, blank=True)
    first_name = models.CharField(_('이름'), max_length=30, blank=True)
    last_name = models.CharField(_('성'), max_length=30, blank=True)
    is_staff = models.BooleanField('스태프 권한', default=False)
    is_active = models.BooleanField('사용중', default=True)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    birthdate = models.DateField(null=True)
    email_verified = models.BooleanField(default=False)
    email_secret = models.CharField(max_length=20, default="", blank=True)
    LOGIN_EMAIL = "email"
    LOGIN_KAKAO = "kakao"
    LOGIN_NAVER = "naver"

    GENDER_MALE = "Male"
    GENDER_FEMALE = "Female"
    GENDER_OTHER = "Other"
    GENDER_CHOICES = (
        (GENDER_MALE, _("Male")),
        (GENDER_FEMALE, _("Female")),
        (GENDER_OTHER, _("Other")),
    )

    LOGIN_CHOICES = (
        (LOGIN_EMAIL, "Email"),
        (LOGIN_NAVER, "Naver"),
        (LOGIN_KAKAO, "Kakao"),
    )

    login_method = models.CharField(
        max_length=6, choices=LOGIN_CHOICES, default=LOGIN_EMAIL
    )

    objects = CustomUserModelManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        swappable = 'AUTH_USER_MODEL'

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def verify_email(self):
        if self.email_verified is False:
            secret = uuid.uuid4().hex[:20]
            self.email_secret = secret
            html_message = render_to_string(
                "email/verify_email.html", {"secret": secret}
            )
            send_mail(
                "Verify CHUNGSOL Account",
                strip_tags(html_message),
                EMAIL_FROM,
                [self.email],
                html_message=html_message,
            )

            self.save()
        return
