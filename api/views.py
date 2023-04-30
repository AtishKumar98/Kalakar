from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from django.contrib.auth import login
from kalaakaar_registration.models import MyUser
from rest_framework.response import Response
from .serializers import UserSerializer,RegisterSerializer,LoginSerializer,CustomAuthTokenSerializer
from django.contrib.auth.models import User
from rest_framework.authentication import TokenAuthentication
from rest_framework import generics
from rest_framework import permissions
from .helpers import *
from rest_framework.authtoken.serializers import AuthTokenSerializer
from knox.views import LoginView as KnoxLoginView
from rest_framework import status
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.contrib.auth import logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Class based view to Get User Details using Token Authentication
def user_details_view(request):
    user = request.user
    if user.is_authenticated:
        data = {
            'phone_number': user.is_admin,
            'email': user.email,
            # Add other user details as needed
        }
        return JsonResponse(data)
    else:
        return JsonResponse({'error': 'User not authenticated'}, status=401)

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
     



@csrf_exempt
def logout_view(request):
    logout(request)
    return JsonResponse({'success': True})

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            username=serializer.validated_data['email'],
            password=serializer.validated_data['password']
            
        )
        if user is None:
            data = {
            'id': user.id,
            'email': user.email,
            # Add other user data as needed
        }
            return Response({'error': 'Invalid credentials'}, status=400)
        if user.choose_a_kalaakaar == 'AN':
           user.choose_a_kalaakaar = "Anchor"
        refresh = RefreshToken.for_user(user)
        return Response({
            'status':"Login Successfull",'id': user.id,
            'email': user.email,
            'full_name':user.full_name,
            'Phone_number': user.Phone_number,
            'Bussiness_name':user.Bussiness_name,
            'city':user.city,
            'choose_a_kalaakaar':user.choose_a_kalaakaar,
            'token': str(refresh.access_token)
        })

# class LoginView(APIView):
#     def post(self, request):
#         username = request.data.get('email')
#         password = request.data.get('password')
#         user = authenticate(request, user=username, password=password)
#         if user:
#             return Response({'token': 'your_token_here'})
#         else:
#             return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
# class CustomObtainAuthToken(ObtainAuthToken):
#     serializer_class = CustomAuthTokenSerializer

#     def post(self, request, *args, **kwargs):
#         serializer = self.serializer_class(data=request.data,
#                                             context={'request': request})
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data['user']
#         token, created = Token.objects.get_or_create(user=user)
#         return Response({'token': token.key}, status=status.HTTP_200_OK)
    
  
    
