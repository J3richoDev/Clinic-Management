from .models import Patient
from django.db.models import Count, Avg
from .models import Patient, MedicalRecord

def get_patient_list(query=None, role_filter=None):
    patients = Patient.objects.all()

    # Apply search query
    if query:
        patients = patients.filter(
            first_name__icontains=query
        ) | patients.filter(
            last_name__icontains=query
        )

    # Apply role filter
    if role_filter:
        patients = patients.filter(role=role_filter)

    return patients
