from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from django.contrib.auth import login
from kalaakaar_registration.models import MyUser
from rest_framework.response import Response
from .serializers import UserSerializer,RegisterSerializer,LoginSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from rest_framework import permissions
from .helpers import *
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken

# Class based view to Get User Details using Token Authentication
class UserDetailAPI(APIView):
  authentication_classes = (TokenAuthentication,)
  permission_classes = (AllowAny,)
  def get(self,request,*args,**kwargs):
    user = MyUser.objects.get(id=request.user.id)
    serializer = UserSerializer(user)
    return Response(serializer.data)

#Class based view to register user
class RegisterUserAPIView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer


class VerifyOtp(APIView):
  
  def post(self, request):
    data = request.data
    phone = data.get('Phone_number')
    print(phone,'PHONE$$$$$$$$')
    user_obj = MyUser.objects.get(Phone_number=phone)
    print(user_obj,'USER$$$$$$$$')
    try:
      data = request.data
      user_obj = MyUser.objects.get(Phone_number=data.get('Phone_number'))
      print(user_obj,'USER$$$$$$$$')
      otp = data.get('otp')
      print('OTTPPPPP$$$$$$$$$$$$$$$$$',otp)
      if user_obj.otp == otp:
        user_obj.is_phone_verified = True
        user_obj.save()
        return Response({'status':200, 'message':'Your OTP is verified'})

      return Response({'status':403, 'message':'Wrong Otp'})

    except Exception as e:
     print(e)
    return Response({'status':404, 'message':'Something Went Wrong'})
  
  
  def patch(self, request):
    try:
      data = request.data
      user_obj = MyUser.objects.filter(Phone_number = data.get('Phone_number'))
      otp = data.get('otp')
      print(data.get('Phone_number'),'%$$$$$$$$$$$$$$$$$')
      print(otp,  'OOOOOOOOOTTTTTTTTP')
      if not user_obj.exists():
         return Response({'status':404, 'message':'user not found'})

      if send_otp_to_mobile(data.get('Phone_number'),user_obj[0]):
        message = f'Your New OTP is {otp}'
        send_OTP(user_obj[0],message)
        return Response({'status':200, 'message':'New OTP sent'})
      return Response({'status':404, 'message':'Try After Few Seconds'})

    except Exception as e:
     print(e)
     


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            username=serializer.validated_data['email'],
            password=serializer.validated_data['password']
        )
        if user is None:
            return Response({'error': 'Invalid credentials'}, status=400)
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        })
