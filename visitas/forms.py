from django import forms
from django.contrib.auth.models import User, Group
from django.contrib.auth.forms import UserCreationForm

class UserCreateForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(required=False)
    password = forms.CharField(widget=forms.PasswordInput, required=True)
    groups = forms.ModelMultipleChoiceField(queryset=Group.objects.all(), required=False)
    is_staff = forms.BooleanField(required=False)
    is_superuser = forms.BooleanField(required=False)

class UserEditForm(forms.Form):
    user_id = forms.IntegerField(widget=forms.HiddenInput)
    username = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(required=False)
    password = forms.CharField(widget=forms.PasswordInput, required=False)
    groups = forms.ModelMultipleChoiceField(queryset=Group.objects.all(), required=False)
    is_staff = forms.BooleanField(required=False)
    is_superuser = forms.BooleanField(required=False)
