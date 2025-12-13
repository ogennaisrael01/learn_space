from ..models import  ClassroomMembership

def classroom_membership(user, classroom, role):
    try:
        membership = ClassroomMembership(user=user, classroom=classroom, role=role) 
        membership.save()
        return {"success": True}
    except Exception as exc:
        return {"success": False, "msg": str(exc)}
    