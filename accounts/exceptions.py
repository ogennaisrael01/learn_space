from rest_framework.exceptions import APIException
from rest_framework import status
from django.utils.translation import gettext_lazy as _


class RequestDataNotPassed(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "Data Not Passed"
    default_detail = _("No data was provided")