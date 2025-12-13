from django.apps import AppConfig


class AppClassroomConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app_classroom'


    def ready(self):
        from . import signals