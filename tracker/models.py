from datetime import timedelta
from django.db import models
from django.utils.timezone import now
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.contrib.contenttypes.models import ContentType


# ✅ User Manager
class UserManager(BaseUserManager):
    def create_user(self, user_id, user_name, password, role=None, **extra_fields):
        if not user_id:
            raise ValueError("User ID is required")
        user = self.model(user_id=user_id, user_name=user_name, **extra_fields)
        user.set_password(password)
        if role:
            user.role = role
        user.save(using=self._db)
        return user

    def create_superuser(self, user_id, user_name, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        admin_role, _ = Role.objects.get_or_create(id=Role.ADMIN, name='Admin')
        return self.create_user(user_id, user_name, password, role=admin_role, **extra_fields)

# ✅ Role Model
class Role(models.Model):
    ADMIN = 1
    MANAGER = 2
    CLIENT = 3
    EMPLOYEE = 4
    USER = 5
    STAFF = 6

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (MANAGER, 'Manager'),
        (CLIENT, 'Client'),
        (EMPLOYEE, 'Employee'),
        (USER, 'User'),
        (STAFF, 'Staff'),
    ]

    id = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, primary_key=True)
    name = models.CharField(max_length=50)

    class Meta:
        ordering = ['id']
        verbose_name_plural = 'Roles'

    def __str__(self):
        return self.get_id_display()

    @classmethod
    def create_missing_roles(cls):
        """Create any missing default roles"""
        existing_roles = set(cls.objects.values_list('id', flat=True))
        for role_id, role_name in cls.ROLE_CHOICES:
            if role_id not in existing_roles:
                cls.objects.create(id=role_id, name=role_name)
                print(f"Created role: {role_name}")

    def get_name_display(self):
        return dict(self.ROLE_CHOICES)[self.id]

    @classmethod
    def setup_permissions(cls):
        """Assigns permissions dynamically based on Django's `Group` model."""
        role_permissions = {
            'Admin': [
                'add_user', 'change_user', 'delete_user', 'view_user',
                'add_group', 'change_group', 'delete_group', 'view_group',
                'transfer_ticket', 'add_priority', 'email_support_team',
                'assign_team_view'
            ],
            'Manager': [
                'view_manager_dashboard',
                'add_user', 'change_user', 'delete_user', 'view_user',
                'transfer_ticket'
            ],
            'Client': ['view_client_dashboard'],
            'Employee': ['view_employee_dashboard'],
            'User': ['view_user_dashboard'],
            'Staff': [
                'view_staff_dashboard',
                'view_ticket',
                'create_ticket',
                'comment_ticket',
                'close_ticket',
                'view_org_tickets'
            ],
        }   

        content_type = ContentType.objects.get_for_model(Role)  # Assigning to Role Model

        for role_name, perms in role_permissions.items():
            group, _ = Group.objects.get_or_create(name=role_name)

            for perm in perms:
                permission, _ = Permission.objects.get_or_create(
                    codename=perm,
                    name=f'Can {perm.replace("_", " ")}',
                    content_type=content_type
                )
                group.permissions.add(permission)  # ✅ Assign permissions to Groups

        print("✅ Permissions assigned to Groups successfully!")

    class Meta:
        permissions = [
            ("view_staff_dashboard", "Can view staff dashboard"),
            ("create_ticket", "Can create ticket"),
            ("view_ticket", "Can view ticket"),
            ("comment_ticket", "Can comment on ticket"),
            ("close_ticket", "Can close ticket"),
            ("view_org_tickets", "Can view organization tickets"),
        ]

    def get_dashboard_permission(self):
        """Get the corresponding dashboard permission for this role"""
        role_name = self.get_name_display().lower()
        return f'view_{role_name}_dashboard'


# ✅ User Model
class UserDetail(AbstractBaseUser, PermissionsMixin):
    row_id = models.AutoField(primary_key=True)  # ✅ `row_id` is the primary key
    user_id = models.CharField(max_length=255, unique=True)
    user_name = models.CharField(max_length=255)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    pagination = models.IntegerField(default=10)
    sorting = models.IntegerField(default=0)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True)
    
    objects = UserManager()

    USERNAME_FIELD = "user_id"
    REQUIRED_FIELDS = ["user_name"]

    def __str__(self):
        return self.user_name

    # ✅ Alias `row_id` as `id` for Django compatibility
    @property
    def id(self):
        return self.row_id

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    # ✅ Override the default related_names
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        related_name='userdetail_set',
        related_query_name='userdetail'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='userdetail_set',
        related_query_name='userdetail'
    )

class Priority(models.Model):
    name = models.CharField(max_length=50, unique=True)
    
    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Priorities"

# ✅ Ticket Model
class Ticket(models.Model):
    STATUS_ACTIVE = 1
    STATUS_CLOSED = 2
    STATUS_PENDING = 3
    
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_CLOSED, 'Closed'),
        (STATUS_PENDING, 'Pending'),
    ]

    id = models.AutoField(primary_key=True)
    subject = models.CharField(max_length=200)
    description = models.TextField()
    created_by = models.ForeignKey(UserDetail, on_delete=models.CASCADE, related_name='created_tickets')
    assigned_to = models.ForeignKey(UserDetail, on_delete=models.SET_NULL, null=True, related_name='assigned_tickets')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.PositiveSmallIntegerField(
        choices=STATUS_CHOICES,
        default=STATUS_ACTIVE
    )
    # Change priority field to ForeignKey
    priority = models.ForeignKey(Priority, on_delete=models.SET_NULL, null=True)
    brand = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"{self.id} - {self.subject}"

    class Meta:
        ordering = ['-created_at']  # Default ordering by creation date, newest first
        indexes = [
            models.Index(fields=['-created_at']),  # Add index for better performance
        ]

# ✅ Ticket Comments Model
class TicketComment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(UserDetail, on_delete=models.CASCADE)
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_internal = models.BooleanField(default=False)

# ✅ Ticket Attachments Model
class TicketAttachment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='attachments')    
    file_name = models.CharField(max_length=255)
    file = models.FileField(upload_to='ticket_attachments/')
    uploaded_by = models.ForeignKey(UserDetail, on_delete=models.CASCADE)
    uploaded_at = models.DateTimeField(auto_now_add=True)

# ✅ Audit Log Model
class AuditLog(models.Model):
    user = models.ForeignKey(UserDetail, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=now)

    def __str__(self):
        return f"{self.user.user_name} - {self.action} at {self.timestamp}"

# ✅ User Settings Model
class UserSettingsModel(models.Model):
    user = models.OneToOneField(UserDetail, on_delete=models.CASCADE, related_name='user_settings')
    pagination = models.IntegerField(default=10)
    sorting = models.IntegerField(default=0)

    def __str__(self):
        return f"Settings for {self.user.user_id}"

    class Meta:
        db_table = 'user_settings'

class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    reset_code = models.CharField(max_length=100, blank=True)
    activation_code = models.CharField(max_length=100, blank=True)
    is_email_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Profile of {self.user.user_id}"



# ✅ Ensure this class exists in `models.py`
class PasswordResetToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens'
    )
    token = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expiration_time = self.created_at + timedelta(hours=24)
        return now() > expiration_time

    def __str__(self):
        return f"Password Reset Token for {self.user.user_id}"

