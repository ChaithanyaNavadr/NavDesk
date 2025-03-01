# Create your views here.

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.mail import send_mail, EmailMessage
from django.core.validators import validate_email
from django.db import connection
from django.db.models import Q, Count
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView, View
from django.template.exceptions import TemplateDoesNotExist

import json
import jwt
import re
import uuid
from datetime import datetime, timedelta

from .decorators import login_required_with_message, role_required, superuser_required
from .models import (
    Role,
    PasswordResetToken, 
    Ticket, 
    UserProfile, 
    TicketAttachment, 
    UserSettingsModel,
    TicketComment,
    UserDetail,
    Priority
)
from .utils import generate_password_reset_token, verify_password_reset_token
from .forms import StaffTicketForm  # Add this import

User = get_user_model()

def home(request):
    return render(request, 'home.html')

@login_required_with_message
def role_based_dashboard(request, role=None):
    """
    Dynamic dashboard view based on user role
    """
    user = request.user
    if not role:
        role = user.role.name.lower() if user.role else 'user'
    
    if not user.role or user.role.name.lower() != role:
        messages.error(request, "Access denied. Invalid role.")
        return redirect('home')
    
    # Prepare context based on role
    context = {'user': user}
    
    if role == 'staff':
        context.update({
            'assigned_tickets': Ticket.objects.filter(assigned_to=user),
            'created_tickets': Ticket.objects.filter(created_by=user)
        })
    elif role == 'admin':
        context.update({
            'all_tickets': Ticket.objects.all(),
            'users': UserDetail.objects.all()
        })
    # Add more role-specific context as needed
    
    try:
        return render(request, f'dashboards/{role}_dashboard.html', context)
    except TemplateDoesNotExist:
        messages.error(request, f"Dashboard template for {role} not found.")
        return redirect('home')

# @role_required([Role.ADMIN])  # Changed from @superuser_required
# def admin_dashboard(request):
#     """Admin dashboard view with statistics"""
#     context = {
#         'total_users': UserDetail.objects.count(),
#         'total_teams': Group.objects.count(),  # Count number of groups
#         'total_tickets': Ticket.objects.filter(status='ACTIVE').count(),
#         'total_priorities': Priority.objects.count(),  # Count number of priorities
#         'user_metrics': get_user_metrics(),
#         'ticket_metrics': get_ticket_metrics(),
#         'recent_tickets': get_recent_tickets()
#     }
#     return render(request, 'dashboards/admin_dashboard.html', context)

@role_required([Role.ADMIN])
def admin_dashboard(request):
    """Admin dashboard view with statistics"""
    context = {
        'total_users': UserDetail.objects.count(),
        'total_teams': Group.objects.count(),
        'total_tickets': Ticket.objects.count(),
        'recent_tickets': Ticket.objects.select_related(
            'created_by',
            'assigned_to',
            'priority'
        ).all().order_by('-created_at'),
        'staff_tickets': Ticket.objects.select_related(
            'created_by',
            'assigned_to',
            'priority'
        ).filter(created_by__role__name='STAFF').order_by('-created_at'),
        'user_tickets': Ticket.objects.select_related(
            'created_by',
            'assigned_to',
            'priority'
        ).filter(created_by__role__name='USER').order_by('-created_at')
    }
    return render(request, 'dashboards/admin_dashboard.html', context)

# def manager_dashboard(request):
#     department = request.user.department
#     context = {
#         'department_users': UserDetail.objects.filter(department=department),
#         'department_tickets': Ticket.objects.filter(
#             Q(created_by__userdetail__department=department) |
#             Q(assigned_to__userdetail__department=department)
#         ),
#         'team_performance': calculate_team_performance(department)
#     }
#     return render(request, 'dashboards/manager_dashboard.html', context)

@role_required([Role.MANAGER])
def manager_dashboard(request):
    return render(request, 'dashboards/manager_dashboard.html')


@role_required([Role.EMPLOYEE])
def employee_dashboard(request):
    return render(request, 'dashboards/employee_dashboard.html')

# def employee_dashboard(request):
#     department = request.user.department
#     context = {
#         'department_tickets': Ticket.objects.filter(
#             Q(created_by__userdetail__department=department) |
#             Q(assigned_to__userdetail__department=department)
#         )
#     }


@role_required([Role.CLIENT])
def client_dashboard(request):
    context = {
        'client_tickets': Ticket.objects.filter(created_by=request.user),
        'resolution_metrics': calculate_resolution_metrics(request.user),
        'sla_metrics': calculate_sla_metrics(request.user)
    }
    return render(request, 'dashboards/client_dashboard.html', context)

@role_required([Role.USER])
def user_dashboard(request):
    context = {
        'assigned_tickets': Ticket.objects.filter(assigned_to=request.user),
        'created_tickets': Ticket.objects.filter(created_by=request.user),
        'recent_activity': TicketComment.objects.filter(
            Q(ticket__assigned_to=request.user) |
            Q(ticket__created_by=request.user)
        ).order_by('-created_at')[:5]
    }
    return render(request, 'dashboards/user_dashboard.html', context)

    
@role_required([Role.STAFF])
def staff_dashboard(request):
    """Staff Dashboard View"""
    context = {
        'assigned_tickets': Ticket.objects.select_related(
            'created_by', 
            'assigned_to',
            'priority'
        ).filter(assigned_to=request.user).order_by('-created_at'),
        
        'created_tickets': Ticket.objects.select_related(
            'created_by', 
            'assigned_to',
            'priority'
        ).filter(created_by=request.user).order_by('-created_at'),
        
        'recent_comments': TicketComment.objects.select_related(
            'ticket', 
            'user'
        ).filter(
            Q(ticket__assigned_to=request.user) |
            Q(ticket__created_by=request.user)
        ).order_by('-created_at')[:5]
    }
    return render(request, 'dashboards/staff_dashboard.html', context)
    
@role_required([Role.STAFF])
def staff_create_ticket(request):
    """Staff can create tickets"""
    if request.method == 'POST':
        form = StaffTicketForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                ticket = form.save(commit=False)
                ticket.created_by = request.user
                ticket.status = 1  # Use numeric value instead of string 'ACTIVE'
                ticket.save()
                
                # Handle file attachments
                files = request.FILES.getlist('attachments')
                for file in files:
                    TicketAttachment.objects.create(
                        ticket=ticket,
                        file=file,
                        file_name=file.name,
                        uploaded_by=request.user
                    )
                
                messages.success(request, f'Ticket #{ticket.id} created successfully.')
                return redirect('staff_dashboard')
            except Exception as e:
                messages.error(request, f'Error creating ticket: {str(e)}')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = StaffTicketForm()
    
    context = {
        'form': form,
        'priorities': Priority.objects.all(),
        'users': UserDetail.objects.filter(is_active=True)
    }
    return render(request, 'staff/create_ticket.html', context)

@permission_required(['tracker.view_ticket', 'tracker.view_org_tickets'])
def staff_view_ticket(request, ticket_id):
    """Staff can view tickets"""
    ticket = get_object_or_404(
        Ticket,
        Q(created_by=request.user) |
        Q(assigned_to=request.user) |
        Q(created_by__department=request.user.department),
        id=ticket_id
    )
    
    context = {
        'ticket': ticket,
        'comments': ticket.comments.all().order_by('-created_at'),
        'can_close': ticket.assigned_to == request.user,
        'can_comment': ticket.assigned_to == request.user or ticket.created_by == request.user
    }
    return render(request, 'staff/view_ticket.html', context)

@permission_required(['tracker.comment_ticket'])
def staff_add_comment(request, ticket_id):
    """Staff can comment on assigned or created tickets"""
    ticket = get_object_or_404(
        Ticket,
        Q(assigned_to=request.user) | Q(created_by=request.user),
        id=ticket_id
    )
    
    if request.method == "POST":
        comment = request.POST.get('comment')
        if comment:
            TicketComment.objects.create(
                ticket=ticket,
                user=request.user,
                comment=comment
            )
            messages.success(request, "Comment added successfully")
        else:
            messages.error(request, "Comment cannot be empty")
            
    return redirect('staff_view_ticket', ticket_id=ticket_id)

@permission_required(['tracker.close_ticket'])
def staff_close_ticket(request, ticket_id):
    """Staff can close assigned tickets"""
    ticket = get_object_or_404(Ticket, assigned_to=request.user, id=ticket_id)
    
    if request.method == "POST":
        resolution = request.POST.get('resolution')
        if resolution:
            ticket.status = 'CLOSED'
            ticket.resolution = resolution
            ticket.closed_at = timezone.now()
            ticket.closed_by = request.user
            ticket.save()
            messages.success(request, f"Ticket #{ticket.id} closed successfully")
        else:
            messages.error(request, "Please provide resolution details")
            
    return redirect('staff_view_ticket', ticket_id=ticket_id)

# Helper functions for metrics
def calculate_team_performance(department):
    # Add implementation
    pass

def calculate_resolution_metrics(user):
    # Add implementation
    pass

def calculate_sla_metrics(user):
    # Add implementation
    pass

def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            login(request, user)
            
            if hasattr(user, 'role') and user.role:
                role = user.role.name.lower()
                return redirect('role_based_dashboard', role=role)
            
            return redirect('role_based_dashboard', role='user')
        else:
            messages.error(request, "Invalid email or password.")
    
    return render(request, "registration/login.html")

def logout_view(request):
    logout(request)
    return redirect("login")

@login_required_with_message
def dashboard(request):
    tickets = Ticket.objects.filter(assigned_to=request.user)
    return render(request, "dashboard/index.html", {"tickets": tickets})


def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email').strip()
        
        try:
            user = User.objects.filter(email__iexact=email).first()
            if user:
                # Generate reset token
                token = generate_reset_token(email)
                reset_link = request.build_absolute_uri(
                    reverse('reset_password') + f'?token={token}'

                )
                
                # Send reset email
                html_message = render_to_string('registration/email/reset_password_email.html', {
                'reset_link': reset_link
                })
                
                email = EmailMessage(
                    'Password Reset Instructions',
                    html_message,
                    settings.EMAIL_HOST_USER,
                    [user.email]
                )
                email.content_subtype = "html"
                email.send(fail_silently=False)
                
                messages.success(request, 'Password reset instructions have been sent to your email.')
                return redirect('login')
            
            messages.error(request, 'No account found with this email address.')
            
        except Exception as e:
            messages.error(request, 'An error occurred. Please try again.')
            
    return render(request, 'registration/forgot_password.html')


def generate_reset_token(email):
    """Generate JWT token for password reset"""
    exp_time = datetime.utcnow() + timedelta(minutes=30)
    return jwt.encode(
        {'email': email, 'exp': exp_time},
        settings.SECRET_KEY,
        algorithm='HS256'
    )

def verify_reset_token(token):
    """Verify JWT token validity"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def reset_password(request):
    """Handle password reset"""
    # Get token from either GET params or POST data
    token = request.GET.get('token') or request.POST.get('token')
    
    if not token:
        messages.error(request, 'Invalid reset link.')
        return redirect('login')

    # Verify token and get email
    email = verify_reset_token(token)
    if not email:
        messages.error(request, 'Invalid or expired reset link. Please request a new one.')
        return redirect('forgot_password')

    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'registration/reset_password.html', {'token': token})
            
        if not validate_password(password):
            messages.error(request, 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            return render(request, 'registration/reset_password.html', {'token': token})
            
        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password has been reset successfully. Please login with your new password.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgot_password')
    
    # For GET request, render the reset password form
    return render(request, 'registration/reset_password.html', {
        'token': token,
        'email': email,
    })

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@login_required_with_message
def change_password(request):
    if request.method == "POST":
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")
        
        if not old_password or not new_password or not confirm_password:
            messages.error(request, "All fields are required.")
            return redirect("change_password")
            
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect("change_password")
            
        if len(new_password) < 8:
            messages.error(request, "Password must be at least  characters long.")
            return redirect("change_password")
            
        if not request.user.check_password(old_password):
            messages.error(request, "Current password is incorrect.")
            return redirect("change_password")
            
        request.user.set_password(new_password)
        request.user.save()
        messages.success(request, "Password changed successfully. Please login again.")
        return redirect("login")
    
    return render(request, "registration/change_password.html")  # Verify this path

def verify_account(request, activation_code):
    try:
        user = User.objects.get(profile__activation_code=activation_code)
        user.profile.is_email_verified = True
        user.profile.activation_code = ""
        user.profile.save()
        messages.success(request, "Account successfully verified.")
    except User.DoesNotExist:
        messages.error(request, "Invalid or expired activation link.")
    return redirect("login")

def new_account(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        
        # Validate inputs
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Please enter a valid email address.")
            return render(request, "registration/new_account.html")
            
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "registration/new_account.html")
            
        if UserDetail.objects.filter(user_id=email).exists():  # Changed from email to user_id
            messages.error(request, "Account with this email already exists.")
            return render(request, "registration/new_account.html")

        # Create new user with default role
        try:
            # Get or create default user role
            default_role, _ = Role.objects.get_or_create(
                id=Role.USER,
                defaults={'name': 'User'}
            )

            # Create user
            user = UserDetail.objects.create_user(
                user_id=email,  # Use email as user_id
                user_name=email.split('@')[0],  # Use part before @ as username
                password=password,
                role=default_role,
                is_active=True,
                is_email_verified=False
            )
            
            # Generate activation code
            activation_code = str(uuid.uuid4())
            
            # Create or update user profile
            UserProfile.objects.update_or_create(
                user=user,
                defaults={
                    'activation_code': activation_code,
                    'is_email_verified': False
                }
            )
            
            # Send activation email
            activation_link = request.build_absolute_uri(
                reverse('verify_account', args=[activation_code])
            )
            send_mail(
                "Activate Your Account",
                f"Click the link below to activate your account: {activation_link}",
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            
            messages.success(request, "Account created successfully. Please check your email to activate your account.")
            return redirect("login")
            
        except Exception as e:
            messages.error(request, f"Error creating account: {str(e)}")
            return render(request, "registration/new_account.html")
            
    return render(request, "registration/new_account.html")


#  this are Tcikets control views
@login_required_with_message
def new_ticket(request):
    if request.method == "POST":
        try:
            # Extract data from POST
            subject = request.POST.get("subject")
            description = request.POST.get("description")
            assignee_value = request.POST.get("assignee")
            priority = request.POST.get("priority", "Medium")
            brand = request.POST.get("brand", "")
            
            # Validate required fields
            if not subject or not description or not assignee_value:
                messages.error(request, "Please fill all required fields")
                return redirect("new_ticket")

            # Handle assignee logic
            if assignee_value == "me":
                assignee = request.user
            elif assignee_value == "team":
                assignee = None  # Handle team assignment as needed
            elif assignee_value == "admin":
                assignee = UserDetail.objects.filter(is_superuser=True).first()
            else:
                try:
                    assignee = UserDetail.objects.get(row_id=assignee_value)  # Changed from id to row_id
                except UserDetail.DoesNotExist:
                    assignee = None

            # Create ticket
            ticket = Ticket.objects.create(
                subject=subject,
                description=description,
                created_by=request.user,
                assigned_to=assignee,
                priority=priority,
                brand=brand,
                status=1
            )

            # Handle file attachments
            files = request.FILES.getlist('attachments')
            for file in files:
                TicketAttachment.objects.create(
                    ticket=ticket,
                    file=file,
                    file_name=file.name,
                    uploaded_by=request.user
                )

            messages.success(request, f"Ticket #{ticket.id} created successfully")
            return redirect("view_ticket", ticket_id=ticket.id)

        except Exception as e:
            messages.error(request, f"Error creating ticket: {str(e)}")
            return redirect("new_ticket")

    # GET request
    context = {
        'users': UserDetail.objects.filter(is_active=True).exclude(row_id=request.user.row_id)  # Changed from id to row_id
    }
    return render(request, "tickets/new_ticket.html", context)

@login_required_with_message
def all_tickets(request):
    # Only show tickets created by the user
    tickets = Ticket.objects.filter(created_by=request.user).order_by('-created_at')
    return render(request, "tracker/all_tickets.html", {"tickets": tickets})

@login_required_with_message
def advanced_search(request):
    search_query = request.GET.get("search", "")
    search_level = request.GET.get("searchLevel", "")
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_search_Ticket %s, %s, %s", [search_query, request.user.id, search_level])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

@login_required_with_message  # Remove role_required decorator for now
def view_ticket(request, ticket_id):
    ticket = get_object_or_404(Ticket, id=ticket_id)
    context = {
        'ticket': ticket,
        'priority_name': ticket.priority.name if ticket.priority else 'Not Set'
    }
    return render(request, 'tickets/view_ticket.html', context)

@login_required_with_message
def view_ticket_detail(request, ticket_id):
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_select_ticket_by_ticketid %s", [ticket_id])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

@login_required_with_message
def save_ticket(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)  # Parse JSON data

            # Extract data from request
            subject = data.get("subject")
            description = data.get("description")
            assignee_id = data.get("assignee")  # Expecting user ID
            priority = data.get("priority", "Medium")
            brand = data.get("brand", "")

            # Validate required fields
            if not subject or not description:
                return JsonResponse({"error": "Subject and description are required"}, status=400)

            # Create and save the ticket
            ticket = Ticket.objects.create(
                subject=subject,
                description=description,
                created_by=request.user,
                priority=priority,
                brand=brand,
                assignee_id=assignee_id if assignee_id else None
            )

            return JsonResponse({"result": "Success", "ticket_id": ticket.id, "url": "/dashboard"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@login_required_with_message
def update_ticket(request, ticket_id):
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        
        # Only allow creator to edit the ticket
        if ticket.created_by != request.user:
            messages.error(request, "You don't have permission to edit this ticket.")
            return redirect('view_ticket', ticket_id=ticket_id)

        if request.method == "POST":
            # Update ticket fields
            ticket.subject = request.POST.get('subject', ticket.subject)
            ticket.priority = request.POST.get('priority', ticket.priority)
            ticket.status = int(request.POST.get('status', ticket.status))
            
            # Handle assignee
            assignee_id = request.POST.get('assigned_to')
            if assignee_id:
                try:
                    ticket.assigned_to = User.objects.get(id=assignee_id)
                except User.DoesNotExist:
                    ticket.assigned_to = None
            else:
                ticket.assigned_to = None

            ticket.save()

            messages.success(request, "Ticket updated successfully")
            return redirect('view_ticket', ticket_id=ticket_id)

    except Ticket.DoesNotExist:
        messages.error(request, "Ticket not found")
        return redirect('all_tickets')

@login_required_with_message
def delete_ticket(request, ticket_id):
    try:
        # Only allow creator to delete the ticket
        ticket = Ticket.objects.get(id=ticket_id, created_by=request.user)
        ticket.delete()
        messages.success(request, f"Ticket #{ticket_id} deleted successfully")
    except Ticket.DoesNotExist:
        messages.error(request, "Ticket not found or you don't have permission to delete it")
    return redirect('all_tickets')

@login_required_with_message
def user_settings(request):
    # Get or create user settings
    settings, created = UserSettingsModel.objects.get_or_create(
        user=request.user,
        defaults={'pagination': 10, 'sorting': 0}
    )

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            settings.pagination = int(data.get("pagination", 10))
            settings.sorting = int(data.get("sorting", 0))
            settings.save()
            
            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({
                "status": "error", 
                "message": str(e)
            }, status=400)
    
    # Handle GET request
    context = {
        'settings': {
            'pagination': settings.pagination,
            'sorting': settings.sorting
        }
    }
    
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(context['settings'])
    
    return render(request, "registration/user_settings.html", context)

def dictfetchone(cursor):
    row = cursor.fetchone()
    if not row:
        return {"pagination": 10, "sorting": 0}  # Default values
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

def dictfetchone(cursor):
    row = cursor.fetchone()
    if not row:
        return {}
    columns = [col[0] for col in cursor.description]
    return dict(zip(columns, row))

def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# this are Ticketsmloyal views



def index(request):
    return render(request, "index.html")

@login_required_with_message
def mloyal_dashboard(request):
    return render(request, "mloyal_dashboard.html")

@login_required_with_message
def mloyal_view_ticket(request, ticket_id):
    try:
        # Only allow viewing if user is the creator
        ticket = Ticket.objects.get(id=ticket_id, created_by=request.user)
        attachments = TicketAttachment.objects.filter(ticket=ticket)
        comments = ticket.comments.all().order_by('-created_at')

        context = {
            'ticket': ticket,
            'attachments': attachments,
            'comments': comments,
            'status_choices': Ticket.STATUS_CHOICES,
            'priority_choices': Ticket.PRIORITY_CHOICES,
            'can_edit': True,  # Creator can always edit
            'users': User.objects.filter(is_active=True)
        }
        return render(request, "tickets/view_ticket.html", context)
    except Ticket.DoesNotExist:
        messages.error(request, f"Ticket #{ticket_id} not found or you don't have permission to view it")
        return redirect('mloyal_index')

@login_required_with_message
def view_ticket_detail(request, ticket_id):
    with connection.cursor() as cursor:
        cursor.execute("EXEC dbo._sp_select_ticket_by_ticketid %s", [ticket_id])
        results = dictfetchall(cursor)
    return JsonResponse(results, safe=False)

def dictfetchall(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]

@login_required_with_message
def mloyal_search_ticket(request):
    ticket_id = request.GET.get('ticket_id')
    if (ticket_id):
        try:
            # Verify ticket exists and belongs to current user
            ticket = Ticket.objects.get(
                models.Q(created_by=request.user) | models.Q(assigned_to=request.user),
                id=ticket_id
            )
            return redirect('mloyal_view_ticket', ticket_id=ticket_id)
        except Ticket.DoesNotExist:
            messages.error(request, f"Ticket #{ticket_id} not found or you don't have permission to view it.")
            return redirect('mloyal_index')
    return redirect('mloyal_index')

# this are ticket super user views

class TicketSuperUserView(View):
    @method_decorator(superuser_required)
    def get(self, request):
        return render(request, "ticketsuperuser/home.html")

class AdminNewTicketView(View):
    def get(self, request):
        return render(request, "ticketsuperuser/admin_new_ticket.html")

class TicketDashboardView(View):
    def get(self, request, id=None, filtertype="", days="", vtype="", ticketno=""):
        nodes = []
        
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT g.group_id, g.group_name, COUNT(mt.assigned_to) AS Count
                FROM mst_group g
                LEFT JOIN mst_user u ON g.group_id = u.group_id
                LEFT JOIN mst_ticket mt ON mt.assigned_to = u.user_id AND mt.last_status=1
                WHERE g.group_id NOT IN (1) AND g.status_flag = 1
                GROUP BY g.group_id, g.group_name
                ORDER BY g.group_name ASC
            """)
            groups = cursor.fetchall()

        for group in groups:
            nodes.append({"id": group[0], "parent": "#", "text": f"{group[1]} ({group[2]})"})
        
        return render(request, "ticketsuperuser/ticket_dashboard.html", {"nodes": json.dumps(nodes)})

class ViewTicketView(View):
    def get(self, request, ticketid):
        return render(request, "ticketsuperuser/view_ticket.html", {"ticketid": ticketid})

class TicketDataView(View):
    def post(self, request):
        user_id = request.session.get("UserID", "")
        with connection.cursor() as cursor:
            cursor.callproc("_sp_select_TicketData_admin", [user_id])
            results = cursor.fetchall()
        
        return JsonResponse(results, safe=False)

class SaveTicketView(View):
    def post(self, request):
        data = json.loads(request.body)
        ticket_id = data.get("ticket_id")
        assignee = data.get("assignee")
        comment = data.get("comment")
        last_status = data.get("laststatus")
        subject = data.get("subject")
        brand = data.get("brand")
        ccs = data.get("ccs")
        priority = data.get("priority")
        user_id = request.session.get("UserID", "")

        with connection.cursor() as cursor:
            cursor.callproc("_sp_InsertTicket", [
                ticket_id, user_id, assignee, last_status, comment, subject, brand, ccs, priority
            ])
            results = cursor.fetchall()
        
        return JsonResponse({"Success": True, "Newticketno": results[0][0]})

class AllTicketsView(View):
    def get(self, request, user_id):
        sorting = request.session.get("Settings", "").split('$')[1]
        with connection.cursor() as cursor:
            cursor.callproc("_sp_select_dashboardTicket", [user_id, sorting])
            results = cursor.fetchall()
        
        return JsonResponse(results, safe=False)



def update_ticket_template(request):
    """Render the update ticket email template"""
    context = {
        'ticketno': request.GET.get('ticketno'),
        'user_name': request.GET.get('user_name'),
        'created': request.GET.get('created'),
        'comment': request.GET.get('comment'),
        # ...other context variables...
    }
    return render(request, 'template/updateticket.html', context)

def ticket_email_template(request):
    """Render the ticket by email template"""
    context = {
        'ticketno': request.GET.get('ticketno'),
        'laststatus': request.GET.get('status'),
        'requester': request.GET.get('requester'),
        # ...other context variables...
    }
    return render(request, 'template/ticketbyemail.html', context)

def ticket_rows_template(request):
    """Render the ticket rows template"""
    context = {
        'user_name': request.GET.get('user_name'),
        'user_id': request.GET.get('user_id'),
        'created': request.GET.get('created'),
        'comment': request.GET.get('comment'),
    }
    return render(request, 'template/updateticketrows.html', context)

def reset_password_template(request):
    """Render the reset password email template"""
    context = {
        'verifylink': request.GET.get('verifylink'),
    }
    return render(request, 'template/resetpassword.html', context)


#Tcicket super user views


class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/home.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/dashboard.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add dashboard-specific context
        return context

class AnalyticsView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/analytics.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add analytics-specific context
        return context

class AnalyticsDetailView(LoginRequiredMixin, TemplateView):
    template_name = 'ticketsuperuser/analytics_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'type': kwargs.get('type'),
            'id': kwargs.get('id'),
            'from_date': self.request.GET.get('from'),
            'to_date': self.request.GET.get('to')
        })
        return context

class DashboardSummaryView(LoginRequiredMixin, View):
    def get(self, request):
        """Get dashboard summary data"""
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT status_id, status_name, COUNT(*) as count 
                FROM tickets 
                GROUP BY status_id, status_name
            """)
            results = self.dictfetchall(cursor)
        return JsonResponse(results, safe=False)

    def dictfetchall(self, cursor):
        columns = [col[0] for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

class TicketDataView(LoginRequiredMixin, View):
    def post(self, request):
        """Get ticket data for admin dashboard"""
        with connection.cursor() as cursor:
            cursor.callproc('sp_get_admin_ticket_data', [request.user.id])
            results = cursor.fetchall()
        return JsonResponse(results, safe=False)


@permission_required('tracker.can_add_users')
def add_user(request):
    """Admin can add users with role selection"""
    # Initialize role choices at the start
    role_choices = Role.objects.all().values_list('id', 'name').order_by('id')
    context = {"role_choices": role_choices}

    if request.method == "POST":
        email = request.POST.get('email')
        user_name = request.POST.get('user_name')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        role_id = request.POST.get('role')

        # Validate inputs
        if not all([email, user_name, password, role_id]):
            messages.error(request, "All fields are required!")
            return render(request, "admin/add_user.html", context)

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, "admin/add_user.html", context)

        try:
            # Convert and validate role_id
            role_id = int(role_id)
            role = Role.objects.get(id=role_id)

            # Create user
            user = UserDetail.objects.create_user(
                user_id=email,
                user_name=user_name,
                password=password,
                role=role,
                is_active=True
            )

            # Assign user to the correct group
            group_name = role.get_name_display()
            group, _ = Group.objects.get_or_create(name=group_name)
            user.groups.add(group)

            messages.success(request, f"Successfully created user: {user_name} with role {group_name}")
            return redirect('user_list')

        except (ValueError, Role.DoesNotExist):
            messages.error(request, "Invalid role selected.")
        except Exception as e:
            messages.error(request, f"Error creating user: {str(e)}")

        # Return response for POST errors
        return render(request, "admin/add_user.html", context)

    # Return response for GET request
    return render(request, "admin/add_user.html", context)

def total_users(request):
    """Display total number of users"""
    total_users = UserDetail.objects.count()
    return render(request, 'admin/total_users.html', {'total_users': total_users})

@permission_required(['tracker.can_assign_permissions'])
def assign_permissions(request, user_id=None):
    """Assign permissions to users"""
    if user_id is None:
        # List all users if no specific user is selected
        users = UserDetail.objects.all().order_by('user_name')
        return render(request, 'admin/permission_list.html', {'users': users})
    
    user = get_object_or_404(UserDetail, row_id=user_id)
    
    if request.method == 'POST':
        # Get selected permissions from the form
        permission_ids = request.POST.getlist('permissions')
        
        # Clear existing permissions and assign new ones
        user.user_permissions.clear()
        if permission_ids:
            permissions = Permission.objects.filter(id__in=permission_ids)
            user.user_permissions.add(*permissions)
        
        messages.success(request, f'Permissions updated for {user.user_name}')
        return redirect('permission_list')
    
    # Get all available permissions
    content_types = ContentType.objects.filter(
        app_label='tracker'
    )
    permissions = Permission.objects.filter(content_type__in=content_types)
    
    context = {
        'user': user,
        'permissions': permissions,
        'current_permissions': user.user_permissions.all()
    }
    return render(request, 'admin/assign_permissions.html', context)

@permission_required(['tracker.can_manage_groups'])
def create_group(request):
    """Admin can create user groups"""
    if request.method == "POST":
        group_name = request.POST.get("group_name")
        if group_name:
            Group.objects.get_or_create(name=group_name)
            messages.success(request, f"Group '{group_name}' created successfully")
            return redirect("group_list")
        messages.error(request, "Group name cannot be empty")

    return render(request, "admin/create_group.html")

@permission_required(['tracker.can_transfer_tickets'])
def transfer_ticket(request, ticket_id):
    """Transfer ticket to another user"""
    ticket = get_object_or_404(Ticket, id=ticket_id)  # Changed from row_id to id
    users = UserDetail.objects.exclude(row_id=ticket.created_by.row_id)

    if request.method == "POST":
        new_assignee_id = request.POST.get("new_assignee")
        new_assignee = get_object_or_404(UserDetail, row_id=new_assignee_id)  # Keep row_id for UserDetail

        ticket.assigned_to = new_assignee
        ticket.save()

        messages.success(request, f"Ticket #{ticket.id} transferred to {new_assignee.user_name}")
        return redirect("admin_dashboard")

    return render(request, "admin/transfer_ticket.html", {"ticket": ticket, "users": users})

@permission_required(['tracker.can_manage_priorities'])
def add_priority(request):
    """Add a new priority"""
    if request.method == "POST":
        priority_name = request.POST.get("name")
        print(f"Received priority name: {priority_name}")  # Debug print
        print(f"POST data: {request.POST}")  # Debug print
        
        if not priority_name or priority_name.strip() == "":
            messages.error(request, "Priority name cannot be empty.")
            return redirect("add_priority")

        # Save Priority
        try:
            Priority.objects.create(name=priority_name.strip())
            messages.success(request, f"Priority '{priority_name}' added successfully!")
            return redirect("priority_list")
        except Exception as e:
            messages.error(request, f"Error creating priority: {str(e)}")
            return redirect("add_priority")

    return render(request, "admin/add_priority.html")

@permission_required(['tracker.can_manage_priorities'])
def priority_list(request):
    """Display list of all priorities"""
    priorities = Priority.objects.all().order_by('name')
    context = {
        'priorities': priorities,
        'total_priorities': priorities.count()
    }
    return render(request, 'admin/priority_list.html', context)

@permission_required(['tracker.can_email_support'])
def email_support_team(request):
    """Admins can send emails to the support team"""
    if request.method == "POST":
        subject = request.POST.get("subject")
        message = request.POST.get("message")   

        if subject and message:
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                ["support@example.com"]
            )
            messages.success(request, "Email sent successfully!")
            return redirect("admin_dashboard")

        messages.error(request, "Subject and message are required")

    return render(request, "admin/email_support.html")

@role_required([Role.ADMIN])
def user_list(request):
    """Display list of users"""
    users = UserDetail.objects.all().order_by('user_name')
    return render(request, 'admin/user_list.html', {
        'users': users,
        'dashboard_url': reverse('dashboard')  # Add dashboard URL to context
    })

@role_required([Role.ADMIN])
def search_users(request):
    query = request.GET.get('q', '')
    users = UserDetail.objects.filter(
        Q(user_name__icontains=query) | 
        Q(user_id__icontains(query))
    )
    return render(request, 'admin/user_list.html', {'users': users})

@role_required([Role.ADMIN])
def edit_user(request, user_id):
    try:
        user = UserDetail.objects.get(row_id=user_id)
        if request.method == "POST":
            # Handle user update
            user.user_name = request.POST.get('user_name')
            user.role_id = request.POST.get('role')
            user.department = request.POST.get('department')
            user.is_active = request.POST.get('is_active') == 'true'
            user.save()
            messages.success(request, f"User {user.user_name} updated successfully")
            return redirect('user_list')
    except UserDetail.DoesNotExist:
        messages.error(request, "User not found")
        return redirect('user_list')
    
    context = {
        'user': user,
        'roles': Role.ROLE_CHOICES
    }
    return render(request, 'admin/edit_user.html', context)

@role_required([Role.ADMIN])
def delete_user(request, user_id):
    try:
        user = UserDetail.objects.get(row_id=user_id)
        user_name = user.user_name
        user.delete()
        messages.success(request, f"User {user_name} deleted successfully")
    except UserDetail.DoesNotExist:
        messages.error(request, "User not found")
    return redirect('user_list')

@role_required([Role.ADMIN])
def admin_settings(request):
    # Add admin settings implementation
    return render(request, 'admin/settings.html')


def assign_role(user: UserDetail, role_name: str):
    """Assigns a user to a role (Group)"""
    try:
        role = Group.objects.get(name=role_name)
        user.groups.add(role)
        user.save()
        print(f"Assigned {user.user_name} to {role_name}")
    except Group.DoesNotExist:
        print(f"Role {role_name} does not exist!")


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import permission_required
from django.contrib import messages
from tracker.models import UserDetail, Ticket, Role
@permission_required('tracker.view_admin_dashboard', raise_exception=True)  # 🔹 Fix app name
def admin_dashboard(request):
    """Admin Dashboard"""
    context = {
        'total_users': UserDetail.objects.count(),
        'total_tickets': Ticket.objects.count(),
        'recent_tickets': Ticket.objects.order_by('-created_at')[:10],
    }
    return render(request, 'dashboards/admin_dashboard.html', context)


@permission_required('auth.view_group')
def group_list(request):
    """View list of all groups"""
    groups = Group.objects.all().order_by('name')
    context = {
        'groups': groups,
        'total_groups': groups.count()
    }
    return render(request, 'admin/group_list.html', context)

@permission_required(['tracker.can_assign_permissions'])
def assign_user_permissions(request, user_id):
    """Assign permissions to specific user"""
    user = get_object_or_404(UserDetail, row_id=user_id)
    permissions = Permission.objects.all().order_by('content_type', 'codename')
    
    if request.method == 'POST':
        selected_permissions = request.POST.getlist('permissions')
        user.user_permissions.clear()
        if selected_permissions:
            permissions = Permission.objects.filter(id__in=selected_permissions)
            user.user_permissions.add(*permissions)
        
        messages.success(request, f'Permissions updated for {user.user_name}')
        return redirect('permission_list')  # Changed from assign_permissions to permission_list
    
    return render(request, 'admin/assign_permissions.html', {
        'user': user,
        'permissions': permissions,
        'current_permissions': user.user_permissions.all()
    })

@permission_required('auth.change_group', raise_exception=True)
def edit_group(request, group_id):
    """Edit an existing group"""
    group = get_object_or_404(Group, id=group_id)

    if request.method == "POST":
        new_name = request.POST.get("group_name")
        permission_ids = request.POST.getlist("permissions")  # Get selected permissions

        if not new_name:
            messages.error(request, "Group name cannot be empty.")
            return redirect('edit_group', group_id=group.id)

        # Update group name
        group.name = new_name
        group.save()

        # Update permissions
        group.permissions.set(Permission.objects.filter(id__in=permission_ids))

        messages.success(request, f"Group '{group.name}' updated successfully!")
        return redirect('group_list')

    permissions = Permission.objects.all()
    selected_permissions = group.permissions.values_list("id", flat=True)

    return render(request, 'admin/edit_group.html', {
        "group": group,
        "permissions": permissions,
        "selected_permissions": selected_permissions
    })

@permission_required('auth.delete_group', raise_exception=True)
def delete_group(request, group_id):
    """Delete a group"""
    group = get_object_or_404(Group, id=group_id)

    if request.method == "POST":
        group.delete()
        messages.success(request, f"Group '{group.name}' deleted successfully!")
        return redirect('group_list')

    return render(request, 'admin/delete_group.html', {"group": group})

@permission_required(['tracker.can_manage_priorities'])
def delete_priority(request, priority_id):
    """Delete a priority"""
    try:
        priority = Priority.objects.get(id=priority_id)
        priority_name = priority.name
        
        # Check if priority is being used by any tickets
        if Ticket.objects.filter(priority=priority).exists():
            messages.error(request, f"Cannot delete priority '{priority_name}' as it is being used by existing tickets.")
            return redirect('priority_list')
        
        # Delete the priority
        priority.delete()
        messages.success(request, f"Priority '{priority_name}' deleted successfully!")
        
    except Priority.DoesNotExist:
        messages.error(request, "Priority not found.")
    
    return redirect('priority_list')

@permission_required(['tracker.can_assign_team_view'])
def assign_team_view(request, team_id):
    """Assign team view permissions to users"""
    team = get_object_or_404(Group, id=team_id)
    
    if request.method == "POST":
        # Get selected users
        user_ids = request.POST.getlist('users')
        users = UserDetail.objects.filter(row_id__in=user_ids)
        
        # Get the team view permission
        content_type = ContentType.objects.get_for_model(Ticket)
        view_permission = Permission.objects.get(
            codename='view_team_tickets',
            content_type=content_type,
        )
        
        # Assign permissions to selected users
        for user in users:
            user.user_permissions.add(view_permission)
            user.groups.add(team)
        
        messages.success(request, f"Team view permissions assigned to {len(users)} users")
        return redirect('group_list')
    
    # Get users not in the team
    team_users = team.user_set.all()
    available_users = UserDetail.objects.exclude(groups=team)
    
    context = {
        'team': team,
        'available_users': available_users,
        'team_users': team_users
    }
    
    return render(request, 'admin/assign_team_view.html', context)

@permission_required(['tracker.can_assign_permissions'])
def assign_permissions(request):
    """List all users for permission assignment"""
    users = UserDetail.objects.all().order_by('user_name')
    return render(request, 'admin/permission_list.html', {'users': users})

# @permission_required(['tracker.can_assign_permissions'])
# def assign_user_permissions(request, user_id):
#     """Assign permissions to specific user"""
#     user = get_object_or_404(UserDetail, row_id=user_id)
#     permissions = Permission.objects.all().order_by('content_type', 'codename')
    
#     if request.method == 'POST':
#         selected_permissions = request.POST.getlist('permissions')
#         user.user_permissions.clear()
#         user.user_permissions.add(*selected_permissions)
#         messages.success(request, f'Permissions updated for {user.user_name}')
#         return redirect('assign_permissions')
    
#     return render(request, 'admin/assign_permissions.html', {
#         'user': user,
#         'permissions': permissions
#     })

@permission_required(['tracker.can_assign_team_view'])
def assign_team_view(request):
    """List all teams for team view assignment"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

@permission_required(['tracker.can_assign_team_view'])
def assign_team_view_permissions(request, team_id):
    """Assign team view permissions"""
    team = get_object_or_404(Group, id=team_id)
    available_users = UserDetail.objects.exclude(groups=team)
    
    if request.method == 'POST':
        user_ids = request.POST.getlist('users')
        team.user_set.add(*user_ids)
        messages.success(request, f'Team view permissions assigned for {team.name}')
        return redirect('assign_team_view')
    
    return render(request, 'admin/assign_team_view.html', {
        'team': team,
        'available_users': available_users,
        'team_users': team.user_set.all()
    })

@permission_required(['tracker.can_assign_team_view'])
def team_view_list(request):
    """List all teams for team view assignment"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

@permission_required(['tracker.can_assign_team_view'])
def assign_team_view(request, team_id=None):
    """Assign team view permissions to users"""
    if (team_id):
        # Show list of teams if no team_id is provided
        teams = Group.objects.all().order_by('name')
        return render(request, 'admin/team_list.html', {'teams': teams})
    
    # Get specific team and handle permissions
    team = get_object_or_404(Group, id=team_id)
    available_users = UserDetail.objects.exclude(groups=team)
    
    if request.method == 'POST':
        user_ids = request.POST.getlist('users')
        selected_users = UserDetail.objects.filter(row_id__in=user_ids)
        
        # Get the team view permission
        content_type = ContentType.objects.get_for_model(Ticket)
        view_permission = Permission.objects.get(
            codename='view_team_tickets',
            content_type=content_type,
        )
        
        # Assign permissions to selected users
        for user in selected_users:
            user.user_permissions.add(view_permission)
            team.user_set.add(user)
        
        messages.success(request, f'Users added to team {team.name} successfully')
        return redirect('team_list')
    
    context = {
        'team': team,
        'available_users': available_users,
        'team_users': team.user_set.all()
    }
    return render(request, 'admin/assign_team_view.html', context)


def team_list(request):
    """List all teams for team view assignment"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

def permission_list(request):
    """List all permissions for permission assignment"""
    permissions = Permission.objects.all().order_by('content_type', 'codename')
    return render(request, 'admin/permissions_list.html', {'permissions': permissions})

@permission_required(['tracker.can_assign_team_view'])
def team_view_list(request):
    """List all teams for team view assignment"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

@permission_required(['tracker.can_assign_team_view'])
def manage_team_view(request, team_id):
    """Manage team view permissions"""
    team = get_object_or_404(Group, id=team_id)
    # Get all users who aren't in this team
    team_users = UserDetail.objects.filter(groups=team)
    available_users = UserDetail.objects.exclude(groups=team)
    
    if request.method == 'POST':
        user_ids = request.POST.getlist('users')
        selected_users = UserDetail.objects.filter(row_id__in=user_ids)
        
        # Get the team view permission
        content_type = ContentType.objects.get_for_model(Ticket)
        view_permission = Permission.objects.get(
            codename='view_team_tickets',
            content_type=content_type,
        )
        
        # Assign permissions to selected users
        for user in selected_users:
            user.user_permissions.add(view_permission)
            user.groups.add(team)  # Add user to group using the reverse relationship
        
        messages.success(request, f'Users added to team {team.name} successfully')
        return redirect('team_list')
    
    context = {
        'team': team,
        'available_users': available_users,
        'team_users': team_users  # Users already in the team
    }
    return render(request, 'admin/assign_team_view.html', context)

@permission_required(['tracker.can_assign_team_view'])
def team_list(request):
    """List all teams"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

@permission_required(['tracker.can_assign_team_view'])
def team_view_list(request):
    """List teams for view permission assignment"""
    teams = Group.objects.all().order_by('name')
    return render(request, 'admin/team_list.html', {'teams': teams})

@permission_required(['tracker.can_assign_team_view'])
def manage_team_view(request, team_id):
    """Manage team view permissions"""
    try:
        team = Group.objects.get(id=team_id)
        team_users = UserDetail.objects.filter(groups=team)
        available_users = UserDetail.objects.exclude(groups=team)
        
        if request.method == 'POST':
            user_ids = request.POST.getlist('users')
            selected_users = UserDetail.objects.filter(row_id__in=user_ids)
            
            # Get or create the team view permission
            content_type = ContentType.objects.get_for_model(Ticket)
            view_permission, _ = Permission.objects.get_or_create(
                codename='view_team_tickets',
                content_type=content_type,
                defaults={'name': 'Can view team tickets'}
            )
            
            # Assign permissions and add users to group
            for user in selected_users:
                user.user_permissions.add(view_permission)
                user.groups.add(team)
            
            messages.success(request, f'Users added to team {team.name} successfully')
            return redirect('team_list')
        
        context = {
            'team': team,
            'available_users': available_users,
            'team_users': team_users
        }
        return render(request, 'admin/manage_team_view.html', context)
        
    except Group.DoesNotExist:
        messages.error(request, "Team not found")
        return redirect('team_list')

@permission_required(['tracker.can_assign_team_view'])
def remove_team_member(request, team_id, user_id):
    """Remove a user from a team"""
    if request.method == "POST":
        team = get_object_or_404(Group, id=team_id)
        user = get_object_or_404(UserDetail, row_id=user_id)
        
        user.groups.remove(team)
        messages.success(request, f"{user.user_name} removed from {team.name}")
        
    return redirect('manage_team_view', team_id=team_id)

