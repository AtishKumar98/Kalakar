from django.db import models
# from phone_field import PhoneField
from django.core.validators import RegexValidator
from django.contrib.auth.models import User
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser
)


phone_regex = RegexValidator(regex=r'^\+?\d{10,10}$',message="You are allowed to enter 10 digit number only. Dont enter +91 or less than 10 digits")




class MyUserManager(BaseUserManager):
    def create_user(self, email,is_agreed, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            is_agreed=is_agreed,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email,is_agreed, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(
            email,
            password=password,
            is_agreed =is_agreed
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

class MyUser(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
 

    Kalakaar = [
        ("AN", 'Anchor'),
        ("SR", 'Singer'),
        ("CR", 'Choreographer'),
        ("VH", 'Videographer'),
        ("PH", 'Photographer'),
        ("DJ", 'DJ'),
        ("MG", 'Magician'),
        ("MD", 'Mehendi Artist'),
        ("MA", 'Makeup Artist'),
        ("SA", 'Sketch Artist'),
        ("TA", 'Tatoo Artist'),
    ]
    full_name = models.CharField(null=True,max_length=50)
    choose_a_kalaakaar = models.CharField(max_length=2, default='SL', choices = Kalakaar,null=True)
    Bussiness_name = models.CharField(max_length=50,null=True)
    city = models.CharField(null=True,max_length=50)
    Pincode = models.IntegerField(null=True)
    Phone_number = models.CharField(null=True,max_length=10)
    date_of_birth = models.DateField(null=True)
    is_agreed = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['is_agreed' ]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


class Profile(models.Model):
    user = models.OneToOneField(MyUser,on_delete=models.CASCADE)
    phone_number = models.CharField(validators=[phone_regex],max_length=10,unique=True)