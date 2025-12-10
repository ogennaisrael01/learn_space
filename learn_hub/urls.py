
from django.contrib import admin
from django.urls import path, include, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf.urls.static import static
from django.conf import settings


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
    path("api/v1/", include(("accounts.urls", "accounts"), namespace="accounts")),
    path("api/v1/", include("app_classroom.urls"), name="classroom"),
    path("", include("rest_framework.urls"))
]


urlpatterns += [
    path("docs/", schema_view.with_ui("swagger", cache_timeout=0), name="swagger-documentation"),
    path("re_docs/", schema_view.with_ui("redoc", cache_timeout=0), name="redoc-documentation"),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)