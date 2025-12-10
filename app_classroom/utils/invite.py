import string
import random


def invite_code(classroom_name: str):
    """ Word based invite code that will be easy to remember and share for class entry"""
    name = classroom_name.upper() # convert class name to uppercase
    letter_A_Z = string.ascii_uppercase
    
    random_letters = "".join(random.choice(letter_A_Z) for _ in range(4))
    code = f"{name}_ACCESS_{random_letters}"
    return code