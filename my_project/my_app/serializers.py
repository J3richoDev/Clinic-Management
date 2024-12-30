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
        password = validated_data.pop('password', None)

        # Search for matching patient details
        matching_patient = PatientAccount.objects.filter(
            first_name=first_name,
            last_name=last_name,
            age=age,
            sex=sex,
            date_of_birth=date_of_birth
        ).first()

        if matching_patient:
            # Update the existing patient's details
            for key, value in validated_data.items():
                setattr(matching_patient, key, value)
            if password:
                matching_patient.password = make_password(password)
            matching_patient.save()
            return matching_patient

        # Create a new patient record if no match is found
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
            'scheduled_time', 'transaction_time'
        ]
        read_only_fields = ['queue_number', 'transaction_time']
