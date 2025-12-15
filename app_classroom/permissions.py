from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsSupervisorOrStudent(BasePermission):
    """ Custom permission to only allow supervisors of an object to modify it,  students to view and create it."""
    def has_object_permission(self, request, view, obj):
        user = request.user
        # Allow safe methods (Read only) for students and teacher    
        if request.method in SAFE_METHODS:
            return (
                    obj.user == user or 
                    getattr(obj.user, "teacher", None) == user
            )

        # Allow teachers to perform other actions (delete, put, patch)
        return getattr(obj.user, "teacher", None) == user

        
        
