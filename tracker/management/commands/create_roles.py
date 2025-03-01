from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from tracker.models import Role

class Command(BaseCommand):
    help = 'Create default roles and permissions'

    def handle(self, *args, **kwargs):
        # Create roles
        roles = [
            (Role.ADMIN, 'Admin'),
            (Role.MANAGER, 'Manager'),
            (Role.CLIENT, 'Client'),
            (Role.EMPLOYEE, 'Employee'),
            (Role.USER, 'User'),
            (Role.STAFF, 'Staff'),
        ]

        # Get content type for Role model
        content_type = ContentType.objects.get_for_model(Role)

        # Define permissions for each role
        role_permissions = {
            'Staff': [
                'view_staff_dashboard',
                'create_ticket',
                'view_ticket',
                'comment_ticket',
                'close_ticket',
                'view_org_tickets'
            ]
        }

        # Create roles and their groups
        for role_id, role_name in roles:
            # Create role
            role, created = Role.objects.get_or_create(
                id=role_id,
                defaults={'name': role_name}
            )
            self.stdout.write(f'{"Created" if created else "Found"} role: {role_name}')

            # Create group for role
            group, created = Group.objects.get_or_create(name=role_name)
            self.stdout.write(f'{"Created" if created else "Found"} group: {role_name}')

            # Create and assign permissions for specific roles
            if role_name in role_permissions:
                for perm_name in role_permissions[role_name]:
                    # Create permission
                    permission, created = Permission.objects.get_or_create(
                        codename=perm_name,
                        content_type=content_type,
                        defaults={'name': perm_name.replace('_', ' ').title()}
                    )
                    self.stdout.write(f'{"Created" if created else "Found"} permission: {perm_name}')

                    # Add permission to group
                    group.permissions.add(permission)
                    self.stdout.write(f'Added permission {perm_name} to group {role_name}')