# Generated by Django 5.0.4 on 2024-08-09 10:20

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('superadmin', '0026_alter_events_created_at_alter_services_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='events',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 10, 20, 4, 771231, tzinfo=datetime.timezone.utc)),
        ),
        migrations.AlterField(
            model_name='services',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 8, 9, 10, 20, 4, 770181, tzinfo=datetime.timezone.utc)),
        ),
    ]
