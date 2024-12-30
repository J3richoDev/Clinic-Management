from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from .models import CustomUser
from .models import PatientAccount, MedicalRecord
from datetime import date

class ProfilePictureForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['profile_picture']

class CustomUserForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'middle_name', 'last_name']

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name', '')
        return first_name.capitalize()

    def clean_middle_name(self):
        middle_name = self.cleaned_data.get('middle_name', '')
        return middle_name.capitalize()

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name', '')
        return last_name.capitalize()
    
class ProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'middle_name', 'last_name', 'email', 'profile_picture']
        widgets = {
            'first_name': forms.TextInput(attrs={'placeholder': 'First Name'}),
            'middle_name': forms.TextInput(attrs={'placeholder': 'Middle Name'}),
            'last_name': forms.TextInput(attrs={'placeholder': 'Last Name'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email'}),
        }
    
class CustomPasswordChangeForm(PasswordChangeForm):
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label="New Password"
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm New Password'}),
        label="Confirm New Password"
    )

class PatientForm(forms.ModelForm):
    SEX_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
    ]

    STUDENT = 'Student'
    FACULTY = 'Faculty'
    NON_ACADEMIC = 'Non-academic'

    ROLE_CHOICES = [
        (STUDENT, 'Student'),
        (FACULTY, 'Faculty'),
        (NON_ACADEMIC, 'Non-academic'),
    ]
    
    sex = forms.ChoiceField(
        choices=SEX_CHOICES, 
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Sex'})
    )
    date_of_birth = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'placeholder': 'YYYY-MM-DD'})
    )
    age = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'readonly': 'readonly', 'placeholder': 'Auto-calculated'})
    )
    first_name = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Enter First Name'})
    )
    middle_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Enter Middle Name (optional)'})
    )
    last_name = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Enter Last Name'})
    )
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Role'})
    )
    contact_number = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'Enter Contact Number'})
    )
    
    
    class Meta:
        model = PatientAccount
        fields = [
            'first_name', 
            'middle_name', 
            'last_name', 
            'sex', 
            'role', 
            'date_of_birth', 
            'age', 
            'contact_number'
        ]
    
    def clean_age(self):
        dob = self.cleaned_data.get('date_of_birth')
        if dob:
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            return age
        return None

from django import forms
from .models import MedicalRecord

class MedicalRecordForm(forms.ModelForm):
    # Pain Scale Choices (1-10, 10 being the highest)
    PAIN_SCALE_CHOICES = [(i, f'{i}') for i in range(1, 11)]

    TRANSACTION_TYPE_CHOICES = [
        ('Medical Consultation', 'Medical Consultation'),
        ('Dental Consultation', 'Dental Consultation'),
        ('Medical Certificate', 'Medical Certificate'),
        ('Other', 'Other'),
    ]
    
    # Initial Diagnosis Choices
    INITIAL_DIAGNOSIS_CHOICES = [
        ('A2024', 'A2024'),
        ('ABDL DCFT', 'ABDL DCFT (Abdominal Discomfort)'),
        ('Acute Asthma', 'Acute Asthma'),
        ('AGE', 'AGE (Acute Gastroenteritis)'),
        ('Allergy', 'Allergy'),
        ('Animal Bite', 'Animal Bite'),
        ('APE', 'APE (Annual Physical Examination)'),
        ('ATP', 'ATP (Acute Tonsilo-Pharyngitis)'),
        ('Burn', 'Burn'),
        ('Cardiac isorder', 'Cardiac Related Disorder'),
        ('Dental Disorder', 'Dental Disorder'),
        ('Dysmenorrhea', 'Dysmenorrhea'),
        ('Ear Disorder', 'Ear Disorder'),
        ('Epistaxis', 'Epistaxis'),
        ('Eye Disorder', 'Eye Disorder'),
        ('GERD', 'GERD (Gastro-Esophageal Reflux Disease)'),
        ('SRI', 'SRI (Sports Related Injury)'),
        ('Surgical Procedure', 'Surgical Procedure'),
        ('SVI', 'SVI (Systemic Viral Infection)'),
        ('TO Rule-out', 'TO Rule-out'),
        ('Trauma', 'Trauma'),
        ('URTI', 'URTI (Upper Respiratory Tract Infection)'),
    ]

    transaction_type = forms.ChoiceField(
        choices=TRANSACTION_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Transaction Type'})
    )
    details = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter Details', 'rows': 3})
    )
    height = forms.DecimalField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter Height (in cm)'})
    )
    weight = forms.DecimalField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter Weight (in kg)'})
    )
    heart_rate = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter Heart Rate (bpm)'})
    )
    respiratory_rate = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter Respiratory Rate (breaths per min)'})
    )
    temperature = forms.DecimalField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'Enter Temperature (°C)'})
    )
    blood_pressure = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Blood Pressure (e.g., 120/80)'})
    )
    pain_scale = forms.ChoiceField(
        choices=PAIN_SCALE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Pain Scale (1-10)'})
    )
    other_signs = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Enter Other Signs (optional)', 'rows': 2})
    )
    initial_diagnosis = forms.ChoiceField(
        choices=INITIAL_DIAGNOSIS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Initial Diagnosis'})
    )

    class Meta:
        model = MedicalRecord
        fields = [
            'transaction_type', 
            'details', 
            'height', 
            'weight',
            'heart_rate', 
            'respiratory_rate', 
            'temperature', 
            'blood_pressure',
            'pain_scale', 
            'other_signs', 
            'initial_diagnosis'
        ]


from .models import PatientAccount

class PatientAccountForm(forms.ModelForm):
    date_of_birth = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    password = forms.CharField(widget=forms.PasswordInput())
    confirm_password = forms.CharField(widget=forms.PasswordInput(), label="Confirm Password")

    class Meta:
        model = PatientAccount
        fields = [
            'first_name', 'middle_name', 'last_name', 'email', 'address',
            'age', 'sex', 'campus', 'college', 'course_year',
            'emergency_contact', 'relation', 'contact_number', 'blood_type',
            'allergies', 'role'
        ]
        widgets = {
            'sex': forms.Select(choices=[('Male', 'Male'), ('Female', 'Female')]),
            'role': forms.Select(choices=PatientAccount.ROLE_CHOICES),
            'blood_type': forms.Select(choices=[
                ('A+', 'A+'), ('A-', 'A-'),
                ('B+', 'B+'), ('B-', 'B-'),
                ('AB+', 'AB+'), ('AB-', 'AB-'),
                ('O+', 'O+'), ('O-', 'O-')
            ])
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            raise forms.ValidationError("Passwords do not match!")
        
from django import forms
from .models import PatientAccount


class PatientLoginForm(forms.Form):
    email = forms.EmailField(label='Email', widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={'class': 'form-control'}))
