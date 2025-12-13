import string
import random


def invite_code():
    """ Word based invite code that will be easy to remember and share for class entry"""

    letter_A_Z = string.ascii_uppercase
    
    random_letters = "".join(random.choice(letter_A_Z) for _ in range(12))
    code = f"ACCESS_{random_letters}"
    return code