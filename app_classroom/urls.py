from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

routers = DefaultRouter()


urlpatterns = [
    path("classroom/invite/code/", views.SendInviteView.as_view(), name="send-invite-code"),
    path("classroom/invite/classroom/<classroon_id>", views.ClassroomInviteView.as_view(), name="send-invite-url"),
    path("classroom/invite/accept/<invite_token>/", views.AccetpInviteView.as_view(), name="accept-invite"),
    path("classroom/join/code/", views.JoinClasViaCodeView.as_view(), name="join-class")
    
]

# Registered views
urlpatterns += [
    path("", include(routers.urls))
]