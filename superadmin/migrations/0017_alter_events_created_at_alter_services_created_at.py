# Generated by Django 5.0.4 on 2024-08-09 05:17

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('superadmin', '0016_alter_events_created_at_alter_services_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 5, 17, 51, 93589, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='services',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 5, 17, 51, 92575, tzinfo=datetime.timezone.utc)),
        ),
    ]
