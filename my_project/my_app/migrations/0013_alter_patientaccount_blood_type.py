# Generated by Django 5.1.4 on 2024-12-29 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('my_app', '0012_alter_patientaccount_blood_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='patientaccount',
            name='blood_type',
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
