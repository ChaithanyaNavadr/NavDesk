# Generated by Django 5.1.5 on 2025-02-09 19:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='role',
            name='id',
            field=models.PositiveSmallIntegerField(choices=[(1, 'Admin'), (2, 'Manager'), (3, 'Client'), (4, 'User'), (5, 'Employee')], primary_key=True, serialize=False),
        ),
    ]
