from rest_framework.decorators import api_view, permission_classes
from rest_framework import permissions
from django.http import JsonResponse


@api_view(http_method_names=["get"])
@permission_classes(permission_classes=[permissions.AllowAny])
def check_django(request):
    """ 
    a simple view for checking if the project is active and ready to accept other request
    """

    return JsonResponse(
        data={
            "detail": "Django is Running.....",
            "status": "success"
        }, status=200
    )

