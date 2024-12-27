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