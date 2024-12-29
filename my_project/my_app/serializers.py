from rest_framework import serializers
from .models import Patient

class PatientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patient
        fields = '__all__'

from rest_framework import serializers
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
        Hash the password if provided.
        """
        password = validated_data.pop('password', None)
        if password:
            validated_data['password'] = make_password(password)
        return super().create(validated_data)
