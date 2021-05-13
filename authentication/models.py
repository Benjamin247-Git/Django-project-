from django.db import models
from PIL import Image
from django.utils.text import slugify
# Create your models here.
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin)
from django.conf import settings
from django.db import models
from rest_framework_simplejwt.tokens import RefreshToken
# from django.core.files.storage import default_storage as storage
# import io
# from io import BytesIO
# from django.core.files.uploadedfile import InMemoryUploadedFile
# from django_resized import ResizedImageField

class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have a Email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'facebook': 'facebook', 'google': 'google',
                  'twitter': 'twitter', 'email': 'email'}


def author_image_upload(instance, filename):
    title = instance.username
    slug = slugify(title)
    return f"authors_images/{slug}/{filename}"

import random
class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True, blank=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    is_passenger = models.BooleanField(default=False)
    is_driver = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    mobile_no = models.CharField(max_length=20, null=True, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    password_string = models.CharField(null=True, max_length=500)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to=author_image_upload, default='default.jpg', null=True)
    about = models.TextField(max_length=800, null=True, blank=True)
    facebook = models.CharField(null=True, blank=True, max_length=100)
    twitter = models.CharField(null=True, blank=True, max_length=100)
    instagram = models.CharField(null=True, blank=True, max_length=100)
    youtube = models.CharField(null=True, blank=True, max_length=100)
    thumbnail = models.ImageField(upload_to=author_image_upload, default='default.jpg', null=True)
    email_token = models.TextField(null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    key = models.TextField(null=True, blank=True)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    #
    #
    def _get_unique_username(self):
        email = str(self.email)
        user_strng = email.split('@')[0]
        unique_username = user_strng
        num = 1
        while User.objects.filter(username=unique_username).exists():
            unique_username = '{}{}'.format(user_strng, num)
            num += 1
        return unique_username


    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self._get_unique_username()

        if self.first_name:
            if " " in self.first_name:
                st = self.first_name.split(" ")
                joined = ""
                for s in st:
                    joined += s.capitalize()+" "
                self.first_name = joined
            else:
                self.first_name = self.first_name.capitalize()

        if self.last_name:
            if " " in self.last_name:
                pass
            else:
                self.last_name = self.last_name.capitalize()

        if self.state:
            self.state = self.state.capitalize()


        img = Image.open(self.image.path)
        
        
        if self.image:
            if img.height > 300 or img.width > 300:
                output_size = (400, 600)
                img.thumbnail(output_size)
                img.save(self.image.path)
                
                super(User, self).save()
