from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsOwerOrAdmin(BasePermission):
    """"
        Allow access to the owner of the object or admin/staff users.
    """
    def has_object_permission(self, request, view, obj):
        if request.user == obj or request.user.is_superuser or request.user.is_staff:
            return True
        return False

class IsAuthenticatedOrUser(BasePermission):
    """ 
        Allow access to authenticated users to read the view or the user themselves.-
    """
    def has_permission(self, request, view):
        "can only read the view and must be authenticated"
        return request.method in SAFE_METHODS \
            and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        " can only modify their own data"
        if obj.user == request.user:
            return True
        return False

class IsStudent(BasePermission):
    def has_object_permission(self, request, view, obj):
        """  
            - Only allow access to users with a student role.
        """
        if obj.user.is_student:
            return True
        return False

class IsTeacher(BasePermission):
    def has_object_permission(self, request, view, obj):
        """  
            - Only allow access to users with a teacher role.
        """
        if obj.user.is_teacher:
            return True
        return False
    
class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user