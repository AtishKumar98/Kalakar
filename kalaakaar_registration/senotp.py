import requests


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

# Example usage
send_OTP([8652012693, "Main_numbrter"], '3445')