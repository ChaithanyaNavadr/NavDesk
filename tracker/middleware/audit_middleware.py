from django.utils.timezone import now
from tracker.models import AuditLog

class AuditMiddleware:
    """Middleware to log user actions."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if request.user.is_authenticated:
            AuditLog.objects.create(
                user=request.user,
                action=f"Accessed {request.method} {request.path}",
                timestamp=now()
            )

        return response
