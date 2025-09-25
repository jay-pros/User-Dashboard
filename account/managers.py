from django.contrib.auth.models import BaseUserManager
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_('Please Enter a valid email address'))
    
    def create_user(self, email, first_name, last_name, groups=None, password=None, user_permissions=None, **extra_fields):
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(_('Email address must be provided'))
        
        if not first_name:
            raise ValueError(_('First name must be provided'))
        if not last_name:
            raise ValueError(_('Last name must be provided'))
        
        user = self.model(
            email=email,
            first_name=first_name,
            last_name=last_name,
            **extra_fields)
        user.set_password(password)
        user.save(using=self._db)


        if groups:
            user.groups.set(groups)
        if user_permissions:
            user.user_permissions.set(user_permissions)


        return user
    
    def create_superuser(self, email, password, first_name=None, last_name=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)

        # Ensure 'id' is not passed in extra_fields
        extra_fields.pop('id', None)

        if not first_name:
            raise ValueError(_('Superuser must have a first name.'))
        if not last_name:
            raise ValueError(_('Superuser must have a last name.'))

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        user = self.create_user(
            email,
            first_name,
            last_name,
            password=password,
            **extra_fields,
        )

        user.save(using=self._db)
        return user