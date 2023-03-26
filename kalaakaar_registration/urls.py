from django.urls import path
from . import views

urlpatterns = [
    # path('',views.home, name= 'home'),
    path('',views.Registration, name= 'Registration'),
    path('registration/OTP/',views.OTPRegistration, name= 'RegistrationOTP'),
    path('confirmed_user/',views.confirmation, name= 'confirmed_user'),
    # path('login/' , views.loginpage, name = 'loginpage'),
    # path('logout/', views.logoutUser, name='logout'),
    # path('login/otp/',views.otpLogin, name= 'otp-login'),
]
