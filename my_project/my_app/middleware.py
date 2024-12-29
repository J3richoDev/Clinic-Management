from .models import PatientAccount

class PatientAuthenticationMiddleware:
    """
    Middleware to attach authenticated patient to the request object.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        patient_id = request.session.get('patient_id')
        if patient_id:
            try:
                request.patient = PatientAccount.objects.get(id=patient_id)
            except PatientAccount.DoesNotExist:
                request.patient = None
        else:
            request.patient = None
        
        response = self.get_response(request)
        return response
