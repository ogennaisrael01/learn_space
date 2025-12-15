from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers as nested_routers

routers = DefaultRouter()
routers.register(r"classroom", views.ClassroomViewSets, basename="class")

# nested rotuer the join request resource
class_routers = nested_routers.NestedSimpleRouter(routers, r"classroom", lookup="class")
# register the request viewsets
class_routers.register(r"join_requests", views.JoinRequestView, basename="classroom-request")

urlpatterns = [
    path("classroom/invite/code/", views.SendInviteView.as_view(), name="send-invite-code"),
    path("classroom/invite/classroom/<classroon_id>", views.ClassroomInviteView.as_view(), name="send-invite-url"),
    path("classroom/invite/accept/<invite_token>/", views.AccetpInviteView.as_view(), name="accept-invite"),
    path("classroom/join/code/", views.JoinClasViaCodeView.as_view(), name="join-class"),
    
]

# Registered views
urlpatterns += [
    path("", include(routers.urls)),
    path("", include(class_routers.urls))
]