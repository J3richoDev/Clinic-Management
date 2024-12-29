from django.contrib.auth.backends import BaseBackend
from .models import PatientAccount
from django.contrib.auth.hashers import check_password
from django.utils.timezone import now


class PatientAccountBackend(BaseBackend):
    """
    Custom authentication backend for PatientAccount.
    """
    def authenticate(self, request, email=None, password=None):
        try:
            patient = PatientAccount.objects.get(email=email)
            if check_password(password, patient.password):
                # Ensure compatibility with Django auth system
                patient.backend = 'my_app.patientauthentication.PatientAccountBackend'
                return patient
        except PatientAccount.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return PatientAccount.objects.get(pk=user_id)
        except PatientAccount.DoesNotExist:
            return None
