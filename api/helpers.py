import random
from django.core.cache import cache
import requests
import json

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


def send_otp_to_mobile(mobile, user_obj):
    
    if cache.get(mobile):
        return False , cache.ttl(mobile)

    try:
        otp_to_sent =random.randint(100000,999999)
        message = f"Your New OTP is {otp_to_sent}"
        send_OTP(mobile, message)
        cache.set(mobile, otp_to_sent , timeout=60)
        user_obj.otp=otp_to_sent
        user_obj.save()
        return True

    except Exception as e:
        print(e)