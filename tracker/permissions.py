from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from tracker.models import UserDetail, Ticket

def setup_roles():
    """Automatically creates roles and assigns permissions dynamically."""
    roles_permissions = {
        'Super Admin': [
            'add_user', 'delete_user', 'view_user', 
            'assign_permissions', 'create_groups'
        ],
        'Admin': [
            'add_user', 'assign_permissions', 'create_groups', 
            'transfer_tickets', 'add_priority', 'email_support', 
            'assign_team_view', 'view_reports', 'manage_teams'
        ],
        'Ticket Admin': [
            'view_reports', 'manage_teams', 'close_ticket'
        ],
        'Staff User': [
            'create_ticket', 'view_ticket', 'comment_ticket', 'close_ticket'
        ]
    }

    # Content Types
    user_content_type = ContentType.objects.get_for_model(UserDetail)
    ticket_content_type = ContentType.objects.get_for_model(Ticket)

    for role, permissions in roles_permissions.items():
        group, _ = Group.objects.get_or_create(name=role)

        for perm in permissions:
            permission, _ = Permission.objects.get_or_create(
                codename=perm,
                name=f'Can {perm.replace("_", " ")}',
                content_type=ticket_content_type if 'ticket' in perm else user_content_type
            )
            group.permissions.add(permission)

    print("Roles and permissions have been successfully created!")
