# Generated by Django 5.1.5 on 2025-03-01 13:43

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0010_alter_ticket_status'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='ticket',
            options={'ordering': ['-created_at']},
        ),
        migrations.AddField(
            model_name='ticket',
            name='closed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='ticket',
            name='closed_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='closed_tickets', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddIndex(
            model_name='ticket',
            index=models.Index(fields=['-created_at'], name='tracker_tic_created_fdb303_idx'),
        ),
    ]
