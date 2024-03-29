from django.shortcuts import render
from urllib import request
from django.shortcuts import render, redirect
from .forms import *
from django.contrib import messages
# from django.contrib.auth.models import User
from .models import MyUser
from django.contrib.auth import authenticate, login , logout
# from .models import Profile
from django.contrib.auth.decorators import login_required
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import random 
from django.conf import settings
from  Kalaakaar.settings import Email_Password
from django.contrib.auth.hashers import make_password, check_password
import requests
# import pyrebase
import smtplib
import ssl
# import firebase_admin
# from firebase_admin import credentials
# from firebase_admin import firestore



# path_for_cred_cert = './djangokalakar-firebase-adminsdk-ndlr6-e5182f449c.json'
# cred = credentials.Certificate(path_for_cred_cert)
# firebase_admin.initialize_app(cred)

# db = firestore.client()





# config = {
#     "apiKey": "AIzaSyCxKIGyZtQrpM9PDIUnfveErB8quVQ-CgM",

#     "authDomain": "djangokalakar.firebaseapp.com",

#     "projectId": "djangokalakar",

#     "storageBucket": "djangokalakar.appspot.com",

#     "messagingSenderId": "138533441471",
    
#     "databaseURL" : "https://djangokalakar-default-rtdb.firebaseio.com",

#     "appId": "1:138533441471:web:f788a787e58cc0fa701b0a",

#     "measurementId": "G-HY46VV610J"

# }
# firebase = pyrebase.initialize_app(config)
# auth =firebase.auth()
# database = firebase.database()



# def send_OTP(number, message):
#     url = 'https://www.fast2sms.com/dev/bulkV2'
#     payload  = {
#     'sender_id': 'FSTSMS', 
#     'message': message, 
#     'language': 'english',
#     'route': 'p',
#     'numbers': number 
# }
#     headers = {
#     'authorization': '6WE8VQDysDK3v2jgWuACTkuWFoOtIkpuDDgr3Hh1oF32uMSnIyHQdrKSBkmd',
#     'Content-Type': "application/x-www-form-urlencoded",
#     'Cache-Control': "no-cache"
# }
    
    
#     response = requests.request("POST",
#                             url,
#                             data = payload ,
#                             headers = headers)
#                             # load json data from source
#     returned_msg = json.loads(response.text)
#     print(returned_msg['message'])

def send_OTP(numbers, variables_values, route='otp'):
    url = "https://www.fast2sms.com/dev/bulkV2"

    payload = {
        'variables_values': variables_values,
        'route': route,
        'numbers': ','.join(map(str, numbers))
    }

    headers = {
        'authorization': '6WE8VQDysDK3v2jgWuACTkuWFoOtIkpuDDgr3Hh1oF32uMSnIyHQdrKSBkmd',  # Replace with your actual API key
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cache-Control': 'no-cache',
    }

    try:
        response = requests.post(url, data=payload, headers=headers)
        returned_msg = response.json()
        print(returned_msg['message'])
    except Exception as e:
        print(f"Error: {e}")


# Create your views here.

def Registration(request):
   
    # channel_name = database.child('Data').child('Minion').get().val()
    # channel_type = database.child('Data').child('Bor').get().val()
    if request.method == 'POST' and 'registration' in request.POST:
        fm = UserRegistrationForm(request.POST)
        if fm.is_valid():
            e = fm.cleaned_data['email']
            # u = fm.cleaned_data['username']
            p = fm.cleaned_data['password1']
            ag= fm.cleaned_data['is_agreed']
            fl= fm.cleaned_data['full_name']
            ck= fm.cleaned_data['choose_a_kalaakaar']
            bn= fm.cleaned_data['Bussiness_name']
            ct= fm.cleaned_data['city']
            pc= fm.cleaned_data['Pincode']
            request.session['email'] = e
            # request.session['user'] = u
            request.session['password'] = p
            request.session['is_agreed'] = ag
            request.session['full_name'] = fl
            request.session['choose_a_kalaakaar'] = ck
            request.session['Bussiness_name'] = bn
            request.session['city'] = ct
            request.session['Pincode'] = pc
            hashed_pwd = make_password(request.session['password'])
            p_number = fm.cleaned_data['Phone_number']
            request.session['number'] = p_number
            otp = random.randint(100000,999999)
            # print(otp)
            # print(p_number)
            request.session['otp'] = otp
            email = MIMEMultipart()
            email.set_unixfrom('author')
            email['From']="hello@kalaakaar.co"
            email['To']=e
            email['Subject'] = 'OTP for Kalaakaar Registration'
            #   bcc = "siddhu.dhangar@tiss.edu"
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
            server.login('atishkumar@atishkumar.co.in',Email_Password)
            #   server.login('AKIAYNJZLMUQQXPKMG5B','BItsVQqmsAojywKw8YzfvgpMbPyNBhOXgJ1e0Iz/OJB3')
            server.sendmail('atishkumar@atishkumar.co.in', e, email.as_string())
            # print('SENT MAIL','FROM',email['From'],'TO',e ,msg_body)
            # send_OTP(p_number , msg_body)
            send_OTP([p_number, "msg_body"], otp)
            server.quit()
            # print(fms3)
            # for fms in fms3:
            #     doc_reference = db.collection(u'Users').document(fms['Email'])
            #     #  db.collection(u'Users').add(fms)
            #     doc_reference.set(fms)
            return redirect('/registration/OTP/')
        
    else:
        fm = UserRegistrationForm()
        # up = UserProfile()
    context = {'fm':fm}
    
    

    return render (request, 'registration.html',context)



def OTPRegistration(request):
    p_number = request.session.get('number')
    email_address = request.session.get('email')
    if request.method == 'POST' and 'otp-registration' in request.POST:
        u_otp = request.POST['otp']
        otp = request.session.get('otp')
        user = request.session.get('user')
        # print(otp)
        hashed_pwd = make_password(request.session['password'])
        p_number = request.session.get('number')
        ag = request.session.get('is_agreed')
        fl = request.session.get('full_name')
        ck = request.session.get('choose_a_kalaakaar')
        bn = request.session.get('Bussiness_name')
        ct = request.session.get('city')
        pc = request.session.get('Pincode')
        email_address = request.session.get('email')
        if int(u_otp)==otp:
            MyUser.objects.create(email=email_address,password=hashed_pwd,full_name=fl,is_agreed=ag,choose_a_kalaakaar=ck,Bussiness_name=bn,city=ct,Pincode=pc,Phone_number=p_number)
            # user_instance = MyUser.objects.get(email=email_address)
            # print(user_instance, '$$$$$$$$$$')
            # Profile.objects.create(user=user_instance,phone_number=p_number)

            fms3= {
                'Full_Name':fl,
                'Kalaakar':ck,
                'Business Name':bn,
                'City':ct,
                'Pincode':pc,
                'Email':email_address,
                'Password':hashed_pwd,
                'Agreed':ag,
                'Phone_Number':p_number,
            }
            # doc_reference = db.collection(u'Users').document(fms3['Email'])
                #  db.collection(u'Users').add(fms)
            # doc_reference.set(fms3)
            request.session.delete('otp')
            request.session.delete('user')
            request.session.delete('password')
            # fms = MyUser.objects.values()
            # print(fl,'#######$$$$$$$$')
            # print(p_number,'NUMBERRR')
            context = {'fl':fl}
            # simple_email_context = ssl.create_default_context()
            email = MIMEMultipart()
            email.set_unixfrom('author')
            email['From']="hello@kalaakaar.co"
            email['To']=email_address
            email['Subject'] = 'You are registered as Kalaakaar'
            #   bcc = "siddhu.dhangar@tiss.edu"
            mail_pwd="hello@kalaakaar23"
            #   mails_to = ' , '.join(mail_from) if True else you
            # subject_txt = 'Registration Confirmation for %s' %(conference_title)
            # subject_txt = 'You are registered as Kalaakaar'
            # BillingName = str(conf_detail_obj.cr_title) + ' ' +  str(conf_detail_obj.cr_fullname) 
            # msg_body = '\n%s,\n\n A payment of Rs.%s received towards the registration fees for the "%s". Thank you for the payment. Your Registration is confirmed and the registration number is %s.\n\n Note: This is an auto-generated mail, please dot not respond to this email.'%(BillingName,request.POST['amt'],conference_title,request.POST['mer_txn'])
            msg_body = 'Thankyou for registering with us, you are now our Business Partner! \n \n As we are nearing the launch of our app, you will be notified on its launch - after all, you are our cheif guest.\n \n \n Thankyou.'
            # msg = 'Subject:{}\n\n{}'.format(email['Subject'], msg_body)
            email.attach(MIMEText(msg_body))
            server = smtplib.SMTP_SSL('smtpout.secureserver.net',465)
            server.ehlo()
            # server.starttls(context=simple_email_context)
            server.login('atishkumar@atishkumar.co.in',Email_Password)
            #   server.login('AKIAYNJZLMUQQXPKMG5B','BItsVQqmsAojywKw8YzfvgpMbPyNBhOXgJ1e0Iz/OJB3')
            server.sendmail('atishkumar@atishkumar.co.in', email_address, email.as_string())
            print('SENT MAIL','FROM',email['From'],'TO',email_address ,msg_body)
            server.quit()
            # try:
            #     email = MIMEMultipart('text/csv')
            #     mail_from['From']="hello@kalaakaar.co"
            #     #   bcc = "siddhu.dhangar@tiss.edu"
            #     mail_pwd="hello@kalaakaar23"
            #     #   mails_to = ' , '.join(mail_from) if True else you
            #     server = smtplib.SMTP_SSL('smtpout.secureserver.net',465)
            #     # subject_txt = 'Registration Confirmation for %s' %(conference_title)
            #     subject_txt = 'You are registered as Kalaakaar'
            #     # BillingName = str(conf_detail_obj.cr_title) + ' ' +  str(conf_detail_obj.cr_fullname) 
            #     # msg_body = '\n%s,\n\n A payment of Rs.%s received towards the registration fees for the "%s". Thank you for the payment. Your Registration is confirmed and the registration number is %s.\n\n Note: This is an auto-generated mail, please dot not respond to this email.'%(BillingName,request.POST['amt'],conference_title,request.POST['mer_txn'])
            #     msg_body = 'Thanks Kalaakaar for your contribution in our registration, \n\n Soon you will be updated with our app"s launching Date. And we will let you know when to Login with your email and password.'
            #     msg = 'Subject:{}\n\n{}'.format(subject_txt, msg_body)
            #     # server.starttls(context=simple_email_context)
            #     server.login(mail_from,mail_pwd)
            #     #   server.login('AKIAYNJZLMUQQXPKMG5B','BItsVQqmsAojywKw8YzfvgpMbPyNBhOXgJ1e0Iz/OJB3')
            #     server.sendmail(mail_from, email_address, msg)
            #     print('SENT MAIL','FROM',mail_from,'TO',email_address,'msg',msg)
                
            # except:
            #     pass
            # server.quit()
            return redirect('/confirmed_user/',context)
        else:
            messages.error(request, 'Wrong OTP Try Again')
    if request.method == "POST" and 'resend-otp' in request.POST:
        otp = request.session.get('otp')
        message = f"Your Registration OTP for Kalakar is {otp}"
        email = MIMEMultipart()
        email.set_unixfrom('author')
        email['From']="hello@kalaakaar.co"
        email['To']=email_address
        email['Subject'] = 'You are registered as Kalaakaar'
        #   bcc = "siddhu.dhangar@tiss.edu"
        mail_pwd="hello@kalaakaar23"
        #   mails_to = ' , '.join(mail_from) if True else you
        # subject_txt = 'Registration Confirmation for %s' %(conference_title)
        # subject_txt = 'You are registered as Kalaakaar'
        # BillingName = str(conf_detail_obj.cr_title) + ' ' +  str(conf_detail_obj.cr_fullname) 
        # msg_body = '\n%s,\n\n A payment of Rs.%s received towards the registration fees for the "%s". Thank you for the payment. Your Registration is confirmed and the registration number is %s.\n\n Note: This is an auto-generated mail, please dot not respond to this email.'%(BillingName,request.POST['amt'],conference_title,request.POST['mer_txn'])
        msg_body = 'Thankyou for registering with us, you are now our Business Partner! \n \n As we are nearing the launch of our app, you will be notified on its launch - after all, you are our cheif guest.\n \n \n Thankyou.'
        # msg = 'Subject:{}\n\n{}'.format(email['Subject'], msg_body)
        email.attach(MIMEText(msg_body))
        server = smtplib.SMTP_SSL('smtpout.secureserver.net',465)
        server.ehlo()
        # server.starttls(context=simple_email_context)
        server.login('atishkumar@atishkumar.co.in',Email_Password)
        #   server.login('AKIAYNJZLMUQQXPKMG5B','BItsVQqmsAojywKw8YzfvgpMbPyNBhOXgJ1e0Iz/OJB3')
        server.sendmail('atishkumar@atishkumar.co.in', email_address, email.as_string())
        print('SENT MAIL','FROM',email['From'],'TO',email_address ,msg_body)
        server.quit()

    content = {'p_number':p_number,'email_address':email_address}
    return render (request, 'OTP_reg.html',content)


def confirmation ( request ) :
    fl = request.session.get('full_name')
    # print('########$$$$$$$$$$')
    # print(fl)
    context =  {'fl':fl}
    return render(request ,'confirmed_user.html',context)

# def otpLogin (request):
#     if request.method == 'POST':
#          username = request.session['username']
#          password =  request.session['password']
#          otp =  request.session.get('login_otp')
#          u_otp = request.POST ['otp']
#          if int (u_otp) == otp:
#             user = authenticate(request , username =username , password = password )
#             if user is not None :
#                   login (request,user)
#                   request.session.delete ('login_otp')
#                   messages.success (request,'login successfully')
#                   return redirect ('/')
#             else:
#                   messages.error(request,'Wrong OTP')
#     return render ( request ,'login-otp.html')


@login_required(login_url='/login/')
def logoutUser(request):
    logout(request)
    return redirect('/login/')





def loginpage(request):
    if request.method == "POST" and 'form1' in request.POST:
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)
        if user is not None:
            login(request, user)
            request.session.set_expiry(5000)
            return redirect('/home/')
        else:
            messages.error(request, 'INCORRECT EMAIL OR PASSWORD! TRY AGAIN')
    
    context = {}

    return render(request, 'login.html', context)


@login_required(login_url='/login/')
def home(request):
    user_id = request.user.id
    User = MyUser.objects.get(id=user_id)
    context = {'User':User,}
    return render (request, 'home.html', context)



@login_required(login_url='/login/')
def profile(request):
    user_id = request.user.id
    User = MyUser.objects.get(id=user_id)
    context = {'User':User,}
    return render (request, 'profile.html', context)

def privacy_policy(request):
    context = {}
    return render (request, 'privacy_policy.html', context)