from django.urls import path
from . import views

urlpatterns = [
    # path('',views.home, name= 'home'),
    path('',views.Registration, name= 'Registration'),
    path('registration/OTP/',views.OTPRegistration, name= 'RegistrationOTP'),
    path('confirmed_user/',views.confirmation, name= 'login'),
    # path('login/otp/',views.otpLogin, name= 'otp-login'),
]
