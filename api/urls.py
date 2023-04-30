from django.urls import path
from .views import UserDetailAPI,RegisterUserAPIView,VerifyOtp,LoginView
urlpatterns = [
  path("get-details",UserDetailAPI.as_view()),
  path('register',RegisterUserAPIView.as_view()),
  path('VerifY_otp',VerifyOtp.as_view()),
  path('login/', LoginView.as_view(), name='login'),
]


