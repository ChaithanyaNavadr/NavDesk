# Generated by Django 5.1.5 on 2025-02-27 09:11

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tracker', '0002_alter_role_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(max_length=255)),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.DeleteModel(
            name='AllTicket',
        ),
        migrations.DeleteModel(
            name='Assignee',
        ),
        migrations.DeleteModel(
            name='AssigneeTreeView',
        ),
        migrations.DeleteModel(
            name='Brand',
        ),
        migrations.DeleteModel(
            name='Buttons',
        ),
        migrations.RemoveField(
            model_name='changepasswordmodel',
            name='user',
        ),
        migrations.DeleteModel(
            name='DashboardInfo',
        ),
        migrations.DeleteModel(
            name='Files',
        ),
        migrations.DeleteModel(
            name='Priority',
        ),
        migrations.DeleteModel(
            name='ResetPasswordModel',
        ),
        migrations.DeleteModel(
            name='TicketAnalytics',
        ),
        migrations.DeleteModel(
            name='TicketAnalyticsType',
        ),
        migrations.DeleteModel(
            name='TicketDetail',
        ),
        migrations.DeleteModel(
            name='TicketFiles',
        ),
        migrations.DeleteModel(
            name='TicketMain',
        ),
        migrations.DeleteModel(
            name='TicketReply',
        ),
        migrations.RemoveField(
            model_name='ticketsummaryadmin',
            name='ticketsummary_ptr',
        ),
        migrations.DeleteModel(
            name='TicketUpdateData',
        ),
        migrations.DeleteModel(
            name='TicketUser',
        ),
        migrations.DeleteModel(
            name='TicketView',
        ),
        migrations.DeleteModel(
            name='TreeViewMyView',
        ),
        migrations.DeleteModel(
            name='TvGroupList',
        ),
        migrations.DeleteModel(
            name='TvUserListTree',
        ),
        migrations.RemoveField(
            model_name='userresetcode',
            name='user',
        ),
        migrations.AlterModelOptions(
            name='userdetail',
            options={'verbose_name': 'user', 'verbose_name_plural': 'users'},
        ),
        migrations.RemoveField(
            model_name='ticket',
            name='brand',
        ),
        migrations.RemoveField(
            model_name='ticket',
            name='ccs',
        ),
        migrations.RemoveField(
            model_name='userdetail',
            name='brand_id',
        ),
        migrations.RemoveField(
            model_name='userdetail',
            name='change_password',
        ),
        migrations.AlterField(
            model_name='userdetail',
            name='password',
            field=models.CharField(max_length=128, verbose_name='password'),
        ),
        migrations.AddField(
            model_name='auditlog',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.DeleteModel(
            name='ChangePasswordModel',
        ),
        migrations.DeleteModel(
            name='TicketSummary',
        ),
        migrations.DeleteModel(
            name='TicketSummaryAdmin',
        ),
        migrations.DeleteModel(
            name='UserResetCode',
        ),
    ]
