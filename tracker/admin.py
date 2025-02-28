from django.contrib import admin
from tracker.models import (
    Role,
    UserDetail,
    Ticket,
    TicketComment,
    TicketAttachment,
    UserProfile,
    UserSettingsModel,
    AuditLog
)
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

# Role Admin
@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)

# User Detail Admin (Register only ONCE)
@admin.register(UserDetail)
class UserDetailAdmin(BaseUserAdmin):
    list_display = ('user_id', 'user_name', 'role', 'is_active')
    list_filter = ('role', 'is_active')
    search_fields = ('user_id', 'user_name')
    ordering = ('user_id',)

    def get_queryset(self, request):
        """Show different users based on the logged-in admin's role"""
        qs = super().get_queryset(request)
        if request.user.groups.filter(name="Admin").exists():
            return qs  # Admins can see all users
        elif request.user.groups.filter(name="Manager").exists():
            return qs.filter(role__id__in=[Role.CLIENT, Role.USER])  # Managers can only see Clients and Users
        return qs.filter(user_id=request.user.user_id)  # Users can only see their own profile

    def has_add_permission(self, request):
        """Only Admins and Managers can add users"""
        return request.user.groups.filter(name="Admin").exists() or request.user.groups.filter(name="Manager").exists()

    def has_change_permission(self, request, obj=None):
        """Admins and Managers can modify user details"""
        return request.user.groups.filter(name="Admin").exists() or request.user.groups.filter(name="Manager").exists()

    def has_delete_permission(self, request, obj=None):
        """Only Admins can delete users"""
        return request.user.groups.filter(name="Admin").exists()

# Ticket Admin
@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ('id', 'subject', 'status', 'priority', 'created_by', 'assigned_to')
    list_filter = ('status', 'priority', 'created_at')
    search_fields = ('subject', 'description', 'created_by__user_name')

    def get_queryset(self, request):
        """Show different tickets based on the logged-in admin's role"""
        qs = super().get_queryset(request)
        if request.user.groups.filter(name="Admin").exists():
            return qs  # Admins can see all tickets
        elif request.user.groups.filter(name="Manager").exists():
            return qs.filter(assigned_to=request.user)  # Managers only see assigned tickets
        elif request.user.groups.filter(name="Client").exists():
            return qs.filter(created_by=request.user)  # Clients only see their own tickets
        return qs.none()

# Other Admin Registrations
@admin.register(TicketComment)
class TicketCommentAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'user', 'created_at', 'is_internal')
    list_filter = ('is_internal', 'created_at')
    search_fields = ('comment',)

@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    list_display = ('ticket', 'file_name', 'uploaded_by', 'uploaded_at')
    list_filter = ('uploaded_at',)
    search_fields = ('file_name',)

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_email_verified')
    list_filter = ('is_email_verified',)
    search_fields = ('user__email',)

@admin.register(UserSettingsModel)
class UserSettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'pagination', 'sorting')
    search_fields = ('user__email',)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'timestamp')
    search_fields = ('user__user_name', 'action')
