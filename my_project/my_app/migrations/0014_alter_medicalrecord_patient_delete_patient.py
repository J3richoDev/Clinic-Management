# Generated by Django 5.1.3 on 2024-12-29 16:53

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('my_app', '0013_patientaccount_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='medicalrecord',
            name='patient',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='medical_records', to='my_app.patientaccount'),
        ),
        migrations.DeleteModel(
            name='Patient',
        ),
    ]