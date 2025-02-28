import uuid
from django.utils.crypto import get_random_string
from tracker.models import PasswordResetToken
from django.utils.timezone import now

def generate_password_reset_token(user):
    """Generates and stores a unique token for password reset."""
    token = get_random_string(64)
    PasswordResetToken.objects.create(user=user, token=token, created_at=now())
    return token

def verify_password_reset_token(token):
    """Verifies if the provided reset token is valid."""
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
        # Optional: Add expiration check (e.g., token valid for 1 hour)
        return reset_token.user.id
    except PasswordResetToken.DoesNotExist:
        return None
