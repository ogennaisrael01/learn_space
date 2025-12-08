from google.oauth2 import id_token
from google.auth.transport import requests
from .utils.retry_on_failure import retry_request_on_failure
from django.conf import settings

client_id = getattr(settings, "GOOGLE_CLIENT_ID", None)

request = requests.Request()

def google_auth(google_id):
    if google_id is None:
        return {"success": False, "message": "No google token id provided"}
    subs = retry_request_on_failure(id_token.verify_oauth2_token(
        google_id, request, client_id
    ))

    if subs.get("success"):
        return subs.get("data")

    else:
        return {"success": False, "message": subs.get("mesasge")}