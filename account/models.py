from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
# Create your models here.


class StudentUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(_('email address:'), unique=True, max_length=255, null=False, blank=False)
    first_name = models.CharField(_('First Name:'), max_length=100)
    last_name = models.CharField(_('Last Name:'),max_length=100)
    phone_number = models.CharField(_('Phone Number:'), max_length=15, unique=True)
    created_at = models.DateTimeField(_('Created At:'), auto_now_add=True)
    updated_at = models.DateTimeField(_('Updated At:'), auto_now=True)
    is_staff = models.BooleanField(_('Staff:'), default=False)
    is_active = models.BooleanField(_('Active:'),default=True)
    is_verified = models.BooleanField(_('Verified:'), default=False)
    date_joined = models.DateTimeField(_('Date:'), auto_now_add=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = UserManager()

    def __str__(self):
        return self.email