from rest_framework.permissions import BasePermission


class IsOwerOrAdmin(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user == obj or request.user.is_superuser or request.user.is_staff:
            return True
        return False
    