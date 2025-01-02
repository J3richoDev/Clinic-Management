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
        fields = ['username', 'first_name', 'middle_name', 'last_name', 'email', 'profile_picture']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Username'}),
            'first_name': forms.TextInput(attrs={'placeholder': 'First Name'}),
            'middle_name': forms.TextInput(attrs={'placeholder': 'Middle Name'}),
            'last_name': forms.TextInput(attrs={'placeholder': 'Last Name'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email'}),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')

        # Ignore validation if username is empty or not provided
        if not username:
            return username

        # Check for uniqueness if a username is provided
        if CustomUser.objects.filter(username=username).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This username is already taken. Please choose another.")

        return username
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("This email is already taken. Please use another email.")
        return email
    
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
        ('Male', 'Male'),
        ('Female', 'Female'),
    ]

    STUDENT = 'Student'
    FACULTY = 'Faculty'
    NON_ACADEMIC = 'Non-academic'

    ROLE_CHOICES = [
        (STUDENT, 'Student'),
        (FACULTY, 'Faculty'),
        (NON_ACADEMIC, 'Non-academic'),
    ]
    
    # Form Fields with Widgets
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
        """Auto-calculate age from date_of_birth."""
        dob = self.cleaned_data.get('date_of_birth')
        if dob:
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            return age
        return None

    def clean(self):
        """Validate duplicate contact number and duplicate patient details."""
        cleaned_data = super().clean()
        first_name = cleaned_data.get('first_name')
        last_name = cleaned_data.get('last_name')
        role = cleaned_data.get('role')
        date_of_birth = cleaned_data.get('date_of_birth')
        contact_number = cleaned_data.get('contact_number')

        # Validate Duplicate Contact Number
        if contact_number and PatientAccount.objects.filter(contact_number=contact_number).exists():
            self.add_error('contact_number', 'A patient with this contact number already exists.')

        # Validate Duplicate First Name, Last Name, Role, and DOB
        if first_name and last_name and role and date_of_birth:
            if PatientAccount.objects.filter(
                first_name=first_name,
                last_name=last_name,
                role=role,
                date_of_birth=date_of_birth
            ).exists():
                raise forms.ValidationError(
                    "A patient with the same First Name, Last Name, Role, and Date of Birth already exists."
                )
        
        return cleaned_data
    
    
class PatientEditForm(forms.ModelForm):
    date_of_birth = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date'}),
        required=False
    )
    SEX_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
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
    role = forms.ChoiceField(
        choices=ROLE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control', 'placeholder': 'Select Role'})
    )

    class Meta:
        model = PatientAccount
        fields = [
            'address', 'contact_number', 'age', 'sex', 'campus',
            'college', 'course_year', 'emergency_contact',
            'relation', 'emergency_contact_number', 'blood_type',
            'allergies', 'role', 'date_of_birth'
        ]
        widgets = {
            'address': forms.Textarea(attrs={'rows': 3, 'class': 'textarea textarea-bordered'}),
            'contact_number': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'age': forms.NumberInput(attrs={'class': 'input input-bordered'}),
            'campus': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'college': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'course_year': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'emergency_contact': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'relation': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'emergency_contact_number': forms.TextInput(attrs={'class': 'input input-bordered'}),
            'blood_type': forms.Select(choices=[
                ('Unknown', 'Unknown'),
                ('A+', 'A+'), ('A-', 'A-'),
                ('B+', 'B+'), ('B-', 'B-'),
                ('AB+', 'AB+'), ('AB-', 'AB-'),
                ('O+', 'O+'), ('O-', 'O-')
            ]),
            'allergies': forms.Textarea(attrs={'rows': 2, 'class': 'textarea textarea-bordered'}),
        }

    def clean_contact_number(self):
        contact_number = self.cleaned_data.get('contact_number')

        if contact_number:
            # Check if the contact number has changed
            if self.instance.pk and self.instance.contact_number == contact_number:
                # If the number hasn't changed, allow it
                return contact_number

            # Check if the new contact number already exists in other records
            existing = PatientAccount.objects.filter(contact_number=contact_number)
            if self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)  # Exclude current instance

            if existing.exists():
                raise forms.ValidationError("This contact number is already in use.")
        
        return contact_number
    
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
