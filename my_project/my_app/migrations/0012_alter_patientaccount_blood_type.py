# Generated by Django 5.1.4 on 2024-12-29 07:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('my_app', '0011_patientaccount_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='patientaccount',
            name='blood_type',
            field=models.CharField(blank=True, max_length=5, null=True),
        ),
    ]