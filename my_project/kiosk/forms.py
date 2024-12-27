from django.utils.timezone import now
from django import forms
from kiosk.models import Ticket
from datetime import datetime, timedelta
from django.utils.timezone import localtime

class TicketForm(forms.ModelForm):
    class Meta:
        model = Ticket
        fields = ['transaction_type', 'role', 'special_tag', 'certificate_type', 'details', 'scheduled_time']
        widgets = {
            'transaction_type': forms.Select(attrs={'class': 'form-control'}),
            'role': forms.Select(attrs={'class': 'form-control'}),
            'special_tag': forms.Select(attrs={'class': 'form-control'}),
            'certificate_type': forms.Select(attrs={'class': 'form-control'}),
            'details': forms.Textarea(attrs={'class': 'form-control'}),
            'scheduled_time': forms.DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
        }

    def clean_scheduled_time(self):
        scheduled_time = self.cleaned_data.get('scheduled_time')
        if scheduled_time:
            # Validation for past times
            if scheduled_time < now():
                raise forms.ValidationError("Scheduled time cannot be in the past.")
            # Optional: Validate appointment slots (9:00 AM to 5:00 PM)
            
            start_time = datetime.combine(scheduled_time.date(), datetime.min.time()) + timedelta(hours=9)
            end_time = datetime.combine(scheduled_time.date(), datetime.min.time()) + timedelta(hours=17)
            if not (start_time <= scheduled_time <= end_time):
                raise forms.ValidationError("Appointments must be scheduled between 9:00 AM and 5:00 PM.")
        return scheduled_time

    def __init__(self, *args, **kwargs):
        ticket_type = kwargs.pop('ticket_type', None)
        super().__init__(*args, **kwargs)

        # Conditionally display fields
        if ticket_type == 'WALKIN':
            self.fields.pop('scheduled_time')  # Remove scheduled_time for Walk-ins
        elif ticket_type == 'APPOINTMENT':
            self.fields['scheduled_time'].required = True  # Make scheduled_time mandatory for Appointments