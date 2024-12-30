from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend

User = get_user_model()

class StaffAuthenticationBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(username=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None
        
class UsernameOrEmailBackend(BaseBackend):
    """
    Custom authentication backend to allow login with username or email.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        # Check if the username contains "@" to determine if it's an email
        try:
            if "@" in username:
                user = User.objects.get(email=username)
            else:
                user = User.objects.get(username=username)
            
            # Validate password and if the user is active
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        """
        Retrieve a user by their ID.
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def user_can_authenticate(self, user):
        """
        Reject inactive users.
        """
        is_active = getattr(user, 'is_active', False)
        return is_active