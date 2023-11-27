from rest_framework import serializers
from kalaakaar_registration.models import MyUser
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from urllib import request
import requests
import json
import random
from .models import *
from .helpers import  *
from django.contrib.auth import authenticate
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random 
from django.conf import settings
from  Kalaakaar.settings import Email_Password
from django.contrib.auth.hashers import make_password, check_password
import requests
# import pyrebase
import smtplib



# def send_OTP(number, message):
#     url = 'https://www.fast2sms.com/dev/bulkV2'
#     my_data = {
#     'sender_id': 'FSTSMS', 
#     'message': message, 
#     'language': 'english',
#     'route': 'p',
#     'numbers': number 
# }
#     headers = {
#     'authorization': 'ShG0stW0urbiBjedsQmCgGATd1RCDMgCVUwSG9f5rxCCMAJuro5NkR1oIWmi',
#     'Content-Type': "application/x-www-form-urlencoded",
#     'Cache-Control': "no-cache"
# }
    
    
#     response = requests.request("POST",
#                             url,
#                             data = my_data,
#                             headers = headers)
#                             # load json data from source
#     returned_msg = json.loads(response.text)
#     print(returned_msg['message'])




# class UserSerializer(serializers.ModelSerializer):
#   class Meta:
#     model = MyUser
#     fields = ['email', 'password1', 'password2', 'is_agreed' , 'full_name', 'choose_a_kalaakaar', 'Bussiness_name','city','Pincode' ]




class RegisterSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(
    required=True,
    validators=[UniqueValidator(queryset=MyUser.objects.all())]
  )
  password = serializers.CharField(
    write_only=True, required=True, validators=[validate_password])
  password2 = serializers.CharField(write_only=True, required=True)
  
  
  class Meta:
    model = MyUser
    fields = ('id','email', 'password', 'password2',
          'full_name', 'choose_a_kalaakaar','Bussiness_name','city','Pincode','Phone_number','is_agreed','otp')
    extra_kwargs = {
      'email': {'required': True},
      'full_name': {'required': True}
    }
  def validate(self, attrs):
    if attrs['password'] != attrs['password2']:
      raise serializers.ValidationError(
        {"password": "Password fields didn't match."})
    return attrs
  
  def create(self, validated_data):
    send_number = validated_data['Phone_number'],
    email_address=validated_data['email']
    otp = random.randint(100000,999999)
    validated_data['otp'] = otp
    message = f"Your Registration OTP for Kalakar is {otp}"
    email = MIMEMultipart()
    email.set_unixfrom('author')
    email['From']="hello@kalaakaar.co"
    email['To']=email_address
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
    server.sendmail('hello@kalaakaar.co', email_address, email.as_string())
    print('SENT MAIL','FROM',email['From'],'TO',email_address ,msg_body)
    server.quit()
    user = MyUser(
      email=validated_data['email'],
      full_name=validated_data['full_name'],
      choose_a_kalaakaar=validated_data['choose_a_kalaakaar'],
      Phone_number=validated_data['Phone_number'],
      city = validated_data['city'],
      Pincode = validated_data['Pincode'],
      is_agreed = validated_data['is_agreed'],
      otp = validated_data['otp']
    )
    email =validated_data['email']
    
    user.set_password(validated_data['password'])
    return user


# class UserRegistrationSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

#     class Meta:
#         model = MyUser
#         fields = ('username', 'password', 'email', 'first_name', 'last_name')

#     def create(self, validated_data):
#         otp = random.randint(100000,999999)
#         user = MyUser.objects.create_user(
#              email=validated_data['email'],
#       full_name=validated_data['full_name'],
#       choose_a_kalaakaar=validated_data['choose_a_kalaakaar'],
#       Phone_number=validated_data['Phone_number'],
#       city = validated_data['city'],
#       Pincode = validated_data['Pincode'],
#       is_agreed = validated_data['is_agreed'],
#       otp = otp
#         )
#         return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
  

from rest_framework import serializers
from django.contrib.auth import authenticate


class CustomAuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        label=("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                username=email, password=password)

            if not user:
                msg = ('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "email" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs