from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.conf import settings  # Import settings for AUTH_USER_MODEL
from django.db.models import Count
from django.utils import timezone
from django.db import models

from django.db import models
from django.contrib.auth.hashers import make_password

class CustomUserManager(BaseUserManager):
    """
    Custom manager for the CustomUser model to handle admin and regular user queries.
    """
    def get_queryset(self):
        return super().get_queryset()

    def admin_users(self):
        """Return queryset for superusers."""
        return self.filter(is_superuser=True)

    def regular_users(self):
        """Return queryset for non-superusers."""
        return self.filter(is_superuser=False)

    def create_user(self, username, email, password=None, **extra_fields):
        """
        Create and return a regular user with the given details.
        """
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """
        Create and return a superuser with the given details.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(username, email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom user model extending AbstractUser to add additional fields and logic.
    """
    ROLE_CHOICES = [
        ('nurse', 'Nurse'),
        ('dentist', 'Dentist'),
        ('physician', 'Physician'),
        ('patient', 'Patient'),  # Add patient role
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, null=True, blank=True)
    middle_name = models.CharField(max_length=50, null=True, blank=True)
    profile_picture = models.ImageField(
        upload_to='profile_pictures/',
        default='profile_pictures/default.png',
        null=True,
        blank=True
    )
    password_changed = models.BooleanField(default=False)

    username = models.CharField(max_length=255, unique=True, default='default_username')

    objects = CustomUserManager()

    def set_password(self, raw_password):
        """
        Override the set_password method to track password changes.
        """
        super().set_password(raw_password)
        self.password_changed = True

    @property
    def full_name(self):
        """
        Return the user's full name in the desired format.
        """
        middle_initials = self.middle_name if self.middle_name else ""
        return f"{self.first_name} {middle_initials} {self.last_name}".strip()

    def save(self, *args, **kwargs):
        if self.first_name:
            self.first_name = ' '.join([word.capitalize() for word in self.first_name.split()])

        if self.middle_name:
            self.middle_name = ' '.join([word.capitalize() for word in self.middle_name.split()])

        if self.last_name:
            self.last_name = ' '.join([word.capitalize() for word in self.last_name.split()])

        if not self.email:
            middle_initial = (
                ''.join([word[0].lower() for word in self.middle_name.split() if word])
                if self.middle_name else ''
            )
            email_username = (
                f"{self.first_name.lower()}.{self.last_name.lower()}.{middle_initial}"
                .replace(" ", "")
            )
            self.email = f"{email_username}@bulsu.edu.ph"

        super().save(*args, **kwargs)

class PatientAccount(models.Model):
    STUDENT = 'Student'
    FACULTY = 'Faculty'
    NON_ACADEMIC = 'Non-academic'

    ROLE_CHOICES = [
        (STUDENT, 'Student'),
        (FACULTY, 'Faculty'),
        (NON_ACADEMIC, 'Non-academic'),
    ]

    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True, blank=True, null=True)
    address = models.TextField(blank=False, null=False)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    age = models.PositiveIntegerField()
    sex = models.CharField(max_length=10)
    campus = models.CharField(max_length=50, blank=True, null=True)
    college = models.CharField(max_length=50, blank=True, null=True)
    course_year = models.CharField(max_length=50, blank=True, null=True)
    emergency_contact = models.CharField(max_length=50)
    relation = models.CharField(max_length=50)
    emergency_contact_number = models.CharField(max_length=15,  blank=True, null=True)
    blood_type = models.CharField(max_length=20, blank=True, null=True)
    allergies = models.TextField(blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=STUDENT)
    password = models.CharField(max_length=128, blank=True, null=True)  # Nullable and blank allowed
    created_at = models.DateTimeField(auto_now_add=True)
    date_of_birth = models.DateField(blank=True, null=True)
    profile_picture = models.ImageField(
            upload_to='profile_pictures/',
            default='profile_pictures/default.png',
            null=True,
            blank=True
        )

    def save(self, *args, **kwargs):
        """
        Hash the password before saving, if provided.
        """
        if self.password and not self.password.startswith('pbkdf2_sha256$'):
            self.password = make_password(self.password)
        super(PatientAccount, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class MedicalRecord(models.Model):
    patient = models.ForeignKey(PatientAccount, on_delete=models.CASCADE, related_name="medical_records")
    transaction_type = models.CharField(max_length=100)
    date_time = models.DateTimeField(auto_now_add=True)
    attending_staff = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)  # Use AUTH_USER_MODEL
    details = models.TextField()

    # Fields for consultations
    height = models.FloatField(blank=True, null=True)  # In cm
    weight = models.FloatField(blank=True, null=True)  # In kg
    heart_rate = models.IntegerField(blank=True, null=True)  # HR
    respiratory_rate = models.IntegerField(blank=True, null=True)  # RR
    temperature = models.FloatField(blank=True, null=True)  # Temp in Celsius
    blood_pressure = models.CharField(max_length=20, blank=True, null=True)  # e.g., "120/80"
    pain_scale = models.IntegerField(blank=True, null=True)  # Scale from 0 to 10
    other_signs = models.TextField(blank=True, null=True)
    initial_diagnosis = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Record for {self.patient} - {self.transaction_type}"
    
    @property
    def is_active_session(self):
        active_sessions = session.objects.filter(expire_date__gte=timezone.now())
        for session in active_sessions:
            data = session.get_decoded()
            if str(self.id) == str(data.get('_auth_user_id')):
                return True
        return False
    




