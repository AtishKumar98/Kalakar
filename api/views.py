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
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random 
from django.conf import settings
from  Kalaakaar.settings import Email_Password
from django.contrib.auth.hashers import make_password, check_password
import requests
# import pyrebase
import smtplib


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
    phone = data.get('email')
    print(phone,'PHONE$$$$$$$$')
    user_obj = MyUser.objects.get(email=phone)
    print(user_obj,'USER$$$$$$$$')
    try:
      data = request.data
      user_obj = MyUser.objects.get(email=data.get('email'))
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
      user_obj = MyUser.objects.filter(email = data.get('email'))
      otp = data.get('otp')
      print(data.get('email'),'%$$$$$$$$$$$$$$$$$')
      print(otp,  'OOOOOOOOOTTTTTTTTP')
      if not user_obj.exists():
         return Response({'status':404, 'message':'user not found'})

      if send_otp_to_mobile(data.get('email'),user_obj[0]):
        e = data.get('email')
        message = f'Your New OTP is {otp}'
        email = MIMEMultipart()
        email.set_unixfrom('author')
        email['From']="hello@kalaakaar.co"
        email['To']=e
        email['Subject'] = 'Your OTP For Kalaakaar application'
        #   bcc = "siddhu.dhangar@tiss.edu"
        mail_pwd="hello@kalaakaar23"
        #   mails_to = ' , '.join(mail_from) if True else you
        # subject_txt = 'Registration Confirmation for %s' %(conference_title)
        # subject_txt = 'You are registered as Kalaakaar'
        # BillingName = str(conf_detail_obj.cr_title) + ' ' +  str(conf_detail_obj.cr_fullname) 
        # msg_body = '\n%s,\n\n A payment of Rs.%s received towards the registration fees for the "%s". Thank you for the payment. Your Registration is confirmed and the registration number is %s.\n\n Note: This is an auto-generated mail, please dot not respond to this email.'%(BillingName,request.POST['amt'],conference_title,request.POST['mer_txn'])
        msg_body = f'<h3>Your OTP For Kalaakaar is {otp} <h3><br><img src = "https://kalaakaar.co/static/images/Business-logo.png" style="width:10%;height:10%;">'
                # msg = 'Subject:{}\n\n{}'.format(email['Subject'], msg_body)
        email.attach(MIMEText(msg_body,"html"))
        server = smtplib.SMTP_SSL('smtpout.secureserver.net',465)
        server.ehlo()
        # server.starttls(context=simple_email_context)
        server.login('hello@kalaakaar.co',Email_Password)
        #   server.login('AKIAYNJZLMUQQXPKMG5B','BItsVQqmsAojywKw8YzfvgpMbPyNBhOXgJ1e0Iz/OJB3')
        server.sendmail('hello@kalaakaar.co', e, email.as_string())
        print('SENT MAIL','FROM',email['From'],'TO',e ,msg_body)
        server.quit()
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
            'status':"Login Successfull",
            'id': user.id,
            'email': user.email,
            'full_name':user.full_name,
            'Phone_number': user.Phone_number,
            'Image':user.profile_update.url,
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
    
  
    
