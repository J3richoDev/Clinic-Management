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
        current_time = now()
        current_date = current_time.date()

        if not scheduled_time:
            raise forms.ValidationError("Scheduled time is required.")

        # 1️⃣ **Validate that the date is not in the past**
        if scheduled_time.date() < current_date:
            raise forms.ValidationError("The appointment date cannot be in the past.")

        # 2️⃣ **Validate working hours (9 AM - 5 PM)**
        start_time = scheduled_time.replace(hour=9, minute=0, second=0, microsecond=0)
        end_time = scheduled_time.replace(hour=17, minute=0, second=0, microsecond=0)
        if not (start_time <= scheduled_time <= end_time):
            raise forms.ValidationError("Appointments must be scheduled between 9:00 AM and 5:00 PM.")

        # 3️⃣ **If appointment is today, ensure it's at least 3 hours ahead**
        if scheduled_time.date() == current_date:
            three_hours_ahead = current_time + timedelta(hours=3)
            if scheduled_time < three_hours_ahead:
                raise forms.ValidationError("Appointments must be scheduled at least 3 hours in advance for the current day.")

        return scheduled_time

    def __init__(self, *args, **kwargs):
        ticket_type = kwargs.pop('ticket_type', None)
        super().__init__(*args, **kwargs)

        # Conditionally display fields
        if ticket_type == 'WALKIN':
            self.fields.pop('scheduled_time')  # Remove scheduled_time for Walk-ins
        elif ticket_type == 'APPOINTMENT':
            self.fields['scheduled_time'].required = True  # Make scheduled_time mandatory for Appointments