
from django.contrib import admin
from django.urls import path, include, re_path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(
        title="Learm Space API",
        default_version="v1",
        contact=openapi.Contact(email="ogennaisrael@gmail.com"),
        license=openapi.License(name="BSC lisence")
    ),
    permission_classes=[permissions.AllowAny],
    public=True
)

# Admin API
urlpatterns = [
    path('admin/', admin.site.urls),
    path("api/v1/", include("accounts.urls"))
]

# Swagger API Documentation
urlpatterns += [
    re_path(r"^docs/", schema_view.with_ui("swagger", cache_timeout=0), name="swagger-documentation"),
    re_path(r"^re_docs/", schema_view.with_ui("redoc", cache_timeout=0), name="redoc_documentation")
]
