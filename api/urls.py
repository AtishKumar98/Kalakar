from django.urls import path
from .views import VerifyOtp,LoginView,logout_view,user_details_view,submit_data
urlpatterns = [
  path("get-details",user_details_view ),
  path('register',submit_data),
  path('VerifY_otp',VerifyOtp.as_view()),
  path('login/', LoginView.as_view(), name='login'),
   path('logout/', logout_view, name='logout'),
]


