from rest_framework import serializers
from kalaakaar_registration.models import MyUser,Profile
from rest_framework.response import Response
from rest_framework import status
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password



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
          'full_name', 'choose_a_kalaakaar','Bussiness_name','city','Pincode','Phone_number')
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
    user = MyUser.objects.create(
      email=validated_data['email'],
      full_name=validated_data['full_name'],
      choose_a_kalaakaar=validated_data['choose_a_kalaakaar'],
      Phone_number=validated_data['Phone_number'],
      city = validated_data['city'],
      Pincode = validated_data['Pincode'],

    )
    user.set_password(validated_data['password'])
    user.save()
    return user