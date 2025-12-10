class EmailService:
    def __init__(self):
        pass
        
    def send_invite_code(self, code, email, app_name):
        subject = f"INVITE CODE: org{[app_name]}"
        context = {
            "code": code,
            "email": email,
            "app_name": app_name
        }
        return subject, context