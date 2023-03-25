from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import Profile,phone_regex
from .models import MyUser
from django.forms import TextInput,EmailInput,PasswordInput



def email_exists(value):
    if MyUser.objects.filter(email=value).exists():
        raise forms.ValidationError("Profile with same email Already exists")

    
Kalakaar = (
        ("kalaakaari", 'Choose kalaakaari'),
        ("CR", 'Choreographer'),
        ("SR", 'Singer'),
        ("TA", 'Tatoo Artist'),
        ("PH", 'Photographer'),
        ("VH", 'Videographer'),
 )
class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField( validators=[email_exists])
    email.widget.attrs['placeholder'] = "Enter Your Email"
    full_name = forms.CharField()
    full_name.widget.attrs['placeholder'] = "Enter Your Fullname"
    choose_a_kalaakaar = forms.ChoiceField(choices = Kalakaar)
    choose_a_kalaakaar.widget.attrs['placeholder'] = "Select a kalaar"
    Bussiness_name = forms.CharField()
    Bussiness_name.widget.attrs['placeholder'] = "Business Name (if any)"
    city = forms.CharField()
    city.widget.attrs['placeholder'] = "City"
    Pincode = forms.IntegerField()
    Pincode.widget.attrs['placeholder'] = "Pincode"
    

    class Meta:
        model = MyUser
        fields = ['email', 'password1', 'password2', 'is_agreed' , 'full_name', 'choose_a_kalaakaar', 'Bussiness_name','city','Pincode' ]
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter Your Username'}),
        }

    def __init__(self, *args, **kwargs):
        super(UserRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['password1'].widget = forms.PasswordInput(attrs={'placeholder': ("Enter Your Password")})
        self.fields['password2'].widget = forms.PasswordInput(attrs={'placeholder': ("Confirm Your Password")})
        self.fields['Bussiness_name'].required = False
        # self.fields['date_of_birth'] = forms.DateField()


class UserProfile(forms.ModelForm):

    phone_number = forms.CharField(max_length=17,validators=[phone_regex])
    phone_number.widget.attrs['placeholder'] = "Enter Your Phone number"
    class Meta:
        model = Profile
        fields = ['phone_number']