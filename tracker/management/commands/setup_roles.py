from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from tracker.models import Role

class Command(BaseCommand):
    help = 'Set up roles and permissions'

    def handle(self, *args, **options):
        # Create content type for Role model
        content_type = ContentType.objects.get_for_model(Role)

        # Define staff permissions
        staff_permissions = [
            'view_staff_dashboard',
            'create_ticket',
            'view_ticket',
            'comment_ticket',
            'close_ticket',
            'view_org_tickets'
        ]

        # Create permissions
        for perm_name in staff_permissions:
            permission, created = Permission.objects.get_or_create(
                codename=perm_name,
                content_type=content_type,
                defaults={'name': perm_name.replace('_', ' ').title()}
            )
            if created:
                self.stdout.write(f'Created permission: {permission.codename}')

        # Create staff role
        staff_role, created = Role.objects.get_or_create(
            id=Role.STAFF,
            defaults={'name': 'Staff'}
        )
        if created:
            self.stdout.write(f'Created role: Staff')

        # Create staff group
        staff_group, created = Group.objects.get_or_create(name='Staff')
        if created:
            self.stdout.write(f'Created group: Staff')

        # Add permissions to staff group
        permissions = Permission.objects.filter(codename__in=staff_permissions)
        staff_group.permissions.add(*permissions)
        self.stdout.write('Added permissions to Staff group')