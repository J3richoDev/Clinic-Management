# Generated by Django 5.1.3 on 2024-12-30 05:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('kiosk', '0008_alter_ticket_queue_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticket',
            name='checked_in_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]