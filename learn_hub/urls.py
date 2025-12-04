
from django.contrib import admin
from django.urls import path, include, re_path
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions

from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
    openapi.Info(
        title="Learn Space API",
        default_version="v1",
        contact=openapi.Contact(email="ogennaisrael@gmail.com"),
        license=openapi.License(name="BSC License"),
        x_tags=[
            {"name": "Accounts"},
        ],
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    # Admin Panel
    path("admin/", admin.site.urls),

    # APIs and Routes
    path("api/v1/accounts/", include(("accounts.urls", "accounts"), namespace="accounts")),
]


urlpatterns += [
    path("docs/", schema_view.with_ui("swagger", cache_timeout=0), name="swagger-documentation"),
    path("redocs/", schema_view.with_ui("redoc", cache_timeout=0), name="redoc-documentation"),
]

