# Generated by Django 5.1.3 on 2025-01-02 03:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('my_app', '0002_alter_patientaccount_contact_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='patientaccount',
            name='username',
            field=models.CharField(blank=True, max_length=255, null=True, unique=True),
        ),
    ]
