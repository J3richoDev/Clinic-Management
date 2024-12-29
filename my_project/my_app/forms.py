from django import forms
from django.contrib.auth.forms import PasswordChangeForm
from .models import CustomUser
from .models import Patient, MedicalRecord

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
    class Meta:
        model = Patient
        fields = ['first_name', 'last_name', 'role', 'date_of_birth', 'contact_number']

class MedicalRecordForm(forms.ModelForm):
    class Meta:
        model = MedicalRecord
        fields = [
            'transaction_type', 'details', 'height', 'weight',
            'heart_rate', 'respiratory_rate', 'temperature', 'blood_pressure',
            'pain_scale', 'other_signs', 'initial_diagnosis'
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
