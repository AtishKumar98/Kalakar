from django.urls import path
from .views import RegisterUserAPIView,VerifyOtp,LoginView,logout_view,user_details_view
urlpatterns = [
  path("get-details",user_details_view ),
  path('register',RegisterUserAPIView.as_view()),
  path('VerifY_otp',VerifyOtp.as_view()),
  path('login/', LoginView.as_view(), name='login'),
   path('logout/', logout_view, name='logout'),
]


