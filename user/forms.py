from django import forms
from . import models


class SignUpForm(forms.ModelForm):

    """ Sign Up Form """

    class Meta:
        model = models.User
        fields = {
            "email",
            "username",
        }
        widgets = {
            "email": forms.EmailInput(
                attrs={"placeholder": "Email", "required": True, "class": "w-full"}
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    password = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Password"})
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Confirm Password"}),
        label="Confirm Password",
    )
    last_name = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': '성'}),
        label="last_name",
    )
    first_name = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': '이름'}),
        label="first_name",
    )

    def clean__email(self):
        email = self.cleaned_data.get("email")
        try:
            print("ALREADY")
            models.User.objects.get(email=email)
            self.add_error(
                "email", forms.ValidationError("User already exists with that email")
            )
        except models.User.DoesNotExist:
            return email

    def clean__password(self):
        password = self.cleaned_data.get("password")
        password1 = self.cleaned_data.get("password1")

        if password != password1:
            self.add_error(
                "password",
                forms.ValidationError("Password confirmation does not match"),
            )
        else:
            return password

    def save(self):
        user = super().save(commit=False)
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")
        first_name = self.cleaned_data.get("first_name")
        last_name = self.cleaned_data.get("last_name")
        user.username = email
        user.first_name = first_name
        user.last_name = last_name
        user.set_password(password)
        user.save()


class LoginForm(forms.ModelForm):

    """ Login Form """

    class Meta:
        model = models.User
        fields = {"email", "password"}
        widgets = {
            "email": forms.EmailInput(attrs={"placeholder": "Email"}),
            "password": forms.PasswordInput(attrs={"placeholder": "Password"}),
        }

    def clean__email(self):
        email = self.cleaned_data.get("email")
        try:
            models.User.objects.get(email=email)
            return email
        except models.User.DoesNotExist:
            self.add_error("email", forms.ValidationError("User does not exist"))

    def clean(self):
        password = self.cleaned_data.get("password")
        email = self.cleaned_data.get("email")
        try:
            user = models.User.objects.get(email=email)
            if user.check_password(password):
                return self.cleaned_data
            else:
                self.add_error("password", forms.ValidationError("Password is wrong"))
        except models.User.DoesNotExist:
            self.add_error("email", forms.ValidationError("User does not exist"))
        return super().clean()