import random
import string


def otp_token() -> dict:
    string_codes = string.digits + string.ascii_uppercase 
    if string_codes:
        otp_code = "".join(random.choice(string_codes) for _ in range(8))
    return {"success": True, "code": otp_code}

    
