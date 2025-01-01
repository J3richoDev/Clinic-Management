from django.db import models
from django.utils.timezone import now
from datetime import timedelta
from django.db import IntegrityError
import uuid
from django.utils.timezone import localtime

class Ticket(models.Model):
    TICKET_TYPE_CHOICES = [
        ('APPOINTMENT', 'Appointment'),
        ('WALKIN', 'Walk-in'),
    ]

    TRANSACTION_TYPE_CHOICES = [
        ('MEDICAL', 'Medical Consultation'),
        ('DENTAL', 'Dental Consultation'),
        ('CERTIFICATE', 'Certificate'),
        ('OTHER', 'Other'),
    ]

    ROLE_CHOICES = [
        ('FACULTY', 'Faculty'),
        ('PERSONNEL', 'Personnel'),
        ('STUDENT', 'Student'),
    ]

    SPECIAL_TAG_CHOICES = [
        ('PWD', 'Person with Disability'),
        ('SENIOR_CITIZEN', 'Senior Citizen'),
        ('NONE', 'None'),
    ]

    CERTIFICATE_CHOICES = [
        ('ABSENCE', 'Absence'),
        ('EMPLOYMENT', 'Employment'),
        ('OJT', 'OJT'),
        ('OSRA', 'OSRA'),
    ]

    TRANSACTION_GROUP_CHOICES = [
        ('NURSE', 'Nurse'),
        ('DENTIST', 'Dentist'),
        ('PHYSICIAN', 'Physician'),
    ]

    transaction_group = models.CharField(max_length=20, choices=TRANSACTION_GROUP_CHOICES, default='NURSE')
    checked_in = models.BooleanField(default=False)  # New field to track if the patient has been served


    ticket_type = models.CharField(max_length=20, choices=TICKET_TYPE_CHOICES)
    label = models.CharField(max_length=20, blank=True, null=True, default='In Queue')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='STUDENT')
    special_tag = models.CharField(max_length=20, choices=SPECIAL_TAG_CHOICES, default='NONE')
    certificate_type = models.CharField(max_length=20, choices=CERTIFICATE_CHOICES, blank=True, null=True)
    details = models.TextField(blank=True, null=True)
    queue_number = models.CharField(max_length=4, unique=True)
    checked_in_time = models.DateTimeField(blank=True, null=True)  
    created_at = models.DateTimeField(auto_now_add=True)
    transaction_time = models.DateTimeField(default=now)
    scheduled_time = models.DateTimeField(blank=True, null=True)  

    def local_transaction_time(self):
        return localtime(self.transaction_time)
    
    def save(self, *args, **kwargs):
        if not self.queue_number:  # Generate queue number only if not set
            # Get all used queue numbers
            used_numbers = Ticket.objects.values_list('queue_number', flat=True)

            # Find the first unused number
            for i in range(1, 10000):  # Supports up to 9999 queue numbers
                candidate = f"{i:04d}"
                if candidate not in used_numbers:
                    self.queue_number = candidate
                    break

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Ticket {self.queue_number} - {self.transaction_type}"

    def get_priority(self):
        role_priority = {
            'FACULTY': 3,
            'PERSONNEL': 3,
            'STUDENT': 1
        }

        special_tag_priority = {
            'PWD': 1,
            'SENIOR_CITIZEN': 1,
            'NONE': 0
        }

        # Combine role and special tag priorities
        return role_priority.get(self.role, 0) + special_tag_priority.get(self.special_tag, 0)