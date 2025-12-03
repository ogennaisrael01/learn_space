
from rest_framework.request import Request
from django.utils import timezone
import logging
import os
from django.conf import settings
from django.core.cache import cache
from rest_framework.exceptions import PermissionDenied
from  django.http import HttpResponseForbidden


logger = logging.getLogger("request_logger")
class LogRequestMiddleware:
    """MIddle Ware for logging each user request into a file """
    def __init__(self, get_response):
        self.get_response = get_response


    def __call__(self, request: Request, *args, **kwds):
        now = timezone.now()
        user = request.user if request.user.is_authenticated else "Anonymous"
        logger.info(f"User:{user}: Path:{request.path}")

        response = self.get_response(request)
        return response

class RateLimitOtpRequestMiddleware:
    """ Rate limit OTP Request within 24 hours timeframe"""
    def __init__(self, get_response):
        self.get_response = get_response
        self.path = ["api/v1/otp/resend/"]
        self.max_request = getattr(settings, "MAX_TRIES_PER_DAY", 3)
        self.initial_retry = 0

    def __call__(self, request: Request, *args, **kwds):
        # Retrieve the client's IP address from the request metadata
        client_ip = request.META.get("REMOTE_ADDR")

        retries_key = f"user_{client_ip}_retries"
        datetime_key = f"user_{client_ip}_timezone" 

        current_date = timezone.now().today()

        # Check if a cache entry for the user's retries exists
        if not cache.has_key(retries_key):
            cache.set(retries_key, self.initial_retry, timeout=86400) # cache for 24 hours

        if not cache.has_key(datetime_key):
            cache.set(datetime_key, current_date, timeout=86400)
        
        if request.path in self.path:
            retry_var = cache.get(retries_key)
            datetime_var = cache.get(datetime_key)

            if retry_var >= self.max_request and current_date <= datetime_var:
                """ if Exceded maximum retry and done with 24 hours time frame. return 403 error"""
                return HttpResponseForbidden(content="Maximum OTP request Exceeded for today, try again tomorrow")
            cache.incr(retry_var, 1)
                
        response = self.get_response(request)
        return response