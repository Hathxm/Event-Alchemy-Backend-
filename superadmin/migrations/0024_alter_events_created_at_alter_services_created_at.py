# Generated by Django 5.0.4 on 2024-08-09 09:59

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('superadmin', '0023_alter_events_created_at_alter_services_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 9, 59, 12, 948304, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='services',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 9, 59, 12, 947307, tzinfo=datetime.timezone.utc)),
        ),
    ]
