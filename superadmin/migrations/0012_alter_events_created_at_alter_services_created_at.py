# Generated by Django 5.0.4 on 2024-07-31 06:29

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('superadmin', '0011_alter_events_created_at_alter_services_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 7, 31, 6, 29, 19, 419557, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='services',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 7, 31, 6, 29, 19, 418489, tzinfo=datetime.timezone.utc)),
        ),
    ]
