# Generated by Django 5.1.4 on 2024-12-30 15:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('my_app', '0020_merge_20241230_2041'),
    ]

    operations = [
        migrations.AddField(
            model_name='patientaccount',
            name='emergency_contact_number',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]