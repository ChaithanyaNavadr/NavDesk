from django.shortcuts import redirect
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from functools import wraps

def login_required_with_message(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated:
            return function(request, *args, **kwargs)
        messages.error(request, 'Please login to continue.')
        return redirect('login')
    return wrap

def role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to continue.')
                return redirect('login')
            
            if not hasattr(request.user, 'role'):
                messages.error(request, 'User role not configured.')
                return redirect('login')
                
            if request.user.is_superuser or request.user.role.id in allowed_roles:
                return view_func(request, *args, **kwargs)
                
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('role_based_dashboard')
            
        return wrapper
    return decorator

def superuser_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_superuser:
            return function(request, *args, **kwargs)
        messages.error(request, 'Superuser access required.')
        return redirect('dashboard')
    return wrap

def permission_required(permissions):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.has_perms(permissions):
                raise PermissionDenied
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
