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
from .helpers import  *
from django.contrib.auth import authenticate




def send_OTP(number, message):
    url = 'https://www.fast2sms.com/dev/bulkV2'
    my_data = {
    'sender_id': 'FSTSMS', 
    'message': message, 
    'language': 'english',
    'route': 'p',
    'numbers': number 
}
    headers = {
    'authorization': 'ShG0stW0urbiBjedsQmCgGATd1RCDMgCVUwSG9f5rxCCMAJuro5NkR1oIWmi',
    'Content-Type': "application/x-www-form-urlencoded",
    'Cache-Control': "no-cache"
}
    
    
    response = requests.request("POST",
                            url,
                            data = my_data,
                            headers = headers)
                            # load json data from source
    returned_msg = json.loads(response.text)
    print(returned_msg['message'])




class UserSerializer(serializers.ModelSerializer):
  class Meta:
    model = MyUser
    fields = ['email', 'password1', 'password2', 'is_agreed' , 'full_name', 'choose_a_kalaakaar', 'Bussiness_name','city','Pincode' ]




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
    fields = ('email', 'password', 'password2',
          'full_name', 'choose_a_kalaakaar','Bussiness_name','city','Pincode','Phone_number','is_agreed')
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
    otp = random.randint(100000,999999)
    message = f"Your Registration OTP for Kalakar is {otp}"
    send_OTP(send_number,message)
    user = MyUser.objects.create(
      email=validated_data['email'],
      full_name=validated_data['full_name'],
      choose_a_kalaakaar=validated_data['choose_a_kalaakaar'],
      Phone_number=validated_data['Phone_number'],
      city = validated_data['city'],
      Pincode = validated_data['Pincode'],
      is_agreed = validated_data['is_agreed'],
      otp = otp
    )
    
    user.set_password(validated_data['password'])
    user.save()
    return user



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