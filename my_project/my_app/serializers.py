from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .models import PatientAccount
from django.contrib.auth.hashers import make_password

class PatientAccountSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = PatientAccount
        fields = '__all__'
        extra_kwargs = {
            'created_at': {'read_only': True},
        }

    def create(self, validated_data):
        """
        Update the existing patient record if matching details are found.
        Otherwise, create a new patient record.
        """
        # Extract provided details
        first_name = validated_data.get('first_name')
        last_name = validated_data.get('last_name')
        age = validated_data.get('age')
        sex = validated_data.get('sex')
        date_of_birth = validated_data.get('date_of_birth')
        contact_number = validated_data.get('contact_number')
        password = validated_data.pop('password', None)

        # Search for a matching patient based on identity details
        matching_patient = PatientAccount.objects.filter(
            first_name=first_name,
            last_name=last_name,
            age=age,
            sex=sex,
            date_of_birth=date_of_birth
        ).first()

        if matching_patient:
            # If the contact number is the same, retain the existing contact number
            if contact_number == matching_patient.contact_number:
                validated_data.pop('contact_number', None)  # Prevent overriding the contact number

            # If the contact number is different, validate uniqueness
            elif PatientAccount.objects.filter(contact_number=contact_number).exclude(id=matching_patient.id).exists():
                raise serializers.ValidationError({
                    "contact_number": "This contact number is already associated with another patient."
                })

            # Update other patient details
            for key, value in validated_data.items():
                setattr(matching_patient, key, value)
            if password:
                matching_patient.password = make_password(password)
            matching_patient.save()
            return matching_patient

        # Check if contact number already exists for new records
        if contact_number and PatientAccount.objects.filter(contact_number=contact_number).exists():
            raise serializers.ValidationError({
                "contact_number": "This contact number is already associated with another patient."
            })

        # Create a new patient record if no conflict exists
        if password:
            validated_data['password'] = make_password(password)

        return super().create(validated_data)

    # my_app/serializers.py

from rest_framework import serializers
from kiosk.models import Ticket

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = [
            'id', 'ticket_type', 'transaction_type', 'role', 'special_tag',
            'certificate_type', 'details', 'queue_number', 'checked_in',
            'scheduled_time', 'transaction_time', 'transaction_group'
        ]
        read_only_fields = ['queue_number', 'transaction_time']

class PatientAccountListSerializer(serializers.ModelSerializer):
    class Meta:
        model = PatientAccount
        fields = '__all__' 
