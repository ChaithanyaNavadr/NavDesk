from django.core.management.base import BaseCommand
from tracker.models import UserDetail, Role
from django.db import transaction, connection
from django.core.management import call_command
from django.contrib.auth.models import Group

class Command(BaseCommand):
    help = 'Creates an admin user and role if they don\'t exist'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Admin email address', default='admin@example.com')
        parser.add_argument('--password', type=str, help='Admin password', default='admin123')
        parser.add_argument('--name', type=str, help='Admin name', default='System Admin')

    def handle(self, *args, **options):
        try:
            # First, disable foreign key checks at the SQL level
            with connection.cursor() as cursor:
                if connection.vendor == 'sqlite':
                    cursor.execute('PRAGMA foreign_keys = OFF;')

            # Make and apply migrations
            self.stdout.write('Creating and applying migrations...')
            call_command('makemigrations', 'tracker', interactive=False)
            call_command('migrate', interactive=False)

            # Create roles and admin user within a transaction
            with transaction.atomic():
                # Create roles
                self.create_all_roles()

                # Get admin role
                admin_role = Role.objects.get(id=Role.ADMIN)

                email = options['email']
                password = options['password']
                name = options['name']

                # Create admin user
                admin_user, created = UserDetail.objects.get_or_create(
                    user_id=email,
                    defaults={
                        'user_name': name,
                        'role': admin_role,
                        'is_staff': True,
                        'is_superuser': True,
                        'is_active': True,
                        'is_email_verified': True,
                    }
                )

                if created:
                    admin_user.set_password(password)
                    admin_user.save()
                    self.stdout.write(self.style.SUCCESS(f'Created admin user: {email}'))
                else:
                    self.stdout.write(self.style.WARNING(f'Admin user already exists: {email}'))

                # Create Admin group if it doesn't exist
                admin_group, created = Group.objects.get_or_create(name='Admin')
                
                # Add user to Admin group
                admin_user.groups.add(admin_group)

            # Re-enable foreign key checks
            with connection.cursor() as cursor:
                if connection.vendor == 'sqlite':
                    cursor.execute('PRAGMA foreign_keys = ON;')

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error creating admin user: {str(e)}'))
            # Re-enable foreign key checks even if there's an error
            with connection.cursor() as cursor:
                if connection.vendor == 'sqlite':
                    cursor.execute('PRAGMA foreign_keys = ON;')
            raise

    def create_all_roles(self):
        """Create all required roles"""
        roles = [
            (Role.ADMIN, 'Admin'),
            (Role.MANAGER, 'Manager'),
            (Role.CLIENT, 'Client'),
            (Role.USER, 'User'),
        ]

        for role_id, role_name in roles:
            Role.objects.get_or_create(
                id=role_id,
                defaults={'name': role_name}
            )
