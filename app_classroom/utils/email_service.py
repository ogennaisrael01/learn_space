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


    def send_classroom_invite(self, url, email, app_name, invited_by, classroom):
        subject = f"Classroom Invitation from {invited_by} - {app_name}"
        context = {
            "url": url,
            "email": email,
            "app_name": app_name,
            "invited_by": invited_by,
            "classroom": classroom
        }
        return subject, context

    def send_invitation_accepted(self, email, app_name, username):
        subject = f"Invitation Accepted - {app_name}"
        context = {
            "email": email,
            "app_name": app_name,
            "username": username
        }
        return subject, context