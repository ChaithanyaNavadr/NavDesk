from django.urls import path
from . import views
# from .views import ticket_superuser as admin_views

urlpatterns = [
    #  Home URL
    path('', views.home, name='home'),
    # Authentication URLs
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('change-password/', views.change_password, name='change_password'),
    path('verify-account/<str:activation_code>/', views.verify_account, name='verify_account'),
    path('new-account/', views.new_account, name='new_account'),

    # Ticket URLs
    path('ticket/new/', views.new_ticket, name='new_ticket'),
    path('tickets/all/', views.all_tickets, name='all_tickets'),
    path('tickets/search/', views.advanced_search, name='advanced_search'),
    path('ticket/<int:ticket_id>/', views.view_ticket, name='view_ticket'),
    path('ticket/<int:ticket_id>/detail/', views.view_ticket_detail, name='view_ticket_detail'),
    path('ticket/<int:ticket_id>/update/', views.update_ticket, name='update_ticket'),
    path('ticket/<int:ticket_id>/delete/', views.delete_ticket, name='delete_ticket'),
    path('user/settings/', views.user_settings, name='user_settings'),

    # MLoyalty URLs
    path('mloyal/', views.index, name='mloyal_index'),
    path('mloyal/dashboard/', views.mloyal_dashboard, name='mloyal_dashboard'),
    path('mloyal/search/', views.mloyal_search_ticket, name='mloyal_search_ticket'),
    path('mloyal/ticket/<int:ticket_id>/', views.mloyal_view_ticket, name='mloyal_view_ticket'),

    # Super User URLs
    path('admin/', views.TicketSuperUserView.as_view(), name='superuser_home'),
    path('admin/new-ticket/', views.AdminNewTicketView.as_view(), name='admin_new_ticket'),
    path('admin/dashboard/<int:id>/<str:filtertype>/<str:days>/<str:vtype>/<str:ticketno>/', 
         views.TicketDashboardView.as_view(), name='admin_dashboard'),
    path('admin/ticket/<int:ticketid>/', views.ViewTicketView.as_view(), name='admin_view_ticket'),
    path('admin/ticket-data/', views.TicketDataView.as_view(), name='admin_ticket_data'),
    path('admin/save-ticket/', views.SaveTicketView.as_view(), name='admin_save_ticket'),
    path('admin/all-tickets/<int:user_id>/', views.AllTicketsView.as_view(), name='admin_all_tickets'),

    # Template URLs
    path('template/ticket/update/', views.update_ticket_template, name='update_ticket_template'),
    path('template/ticket/email/', views.ticket_email_template, name='ticket_email_template'),
    path('template/ticket/rows/', views.ticket_rows_template, name='ticket_rows_template'),
    path('template/reset-password/', views.reset_password_template, name='reset_password_template'),
    
    # Role-based dashboard URLs
    path('dashboard/', views.role_based_dashboard, name='role_based_dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('manager/dashboard/', views.manager_dashboard, name='manager_dashboard'),
    path('client/dashboard/', views.client_dashboard, name='client_dashboard'),
    path('user/dashboard/', views.user_dashboard, name='user_dashboard'),
    path('employee/dashboard/', views.employee_dashboard, name='employee_dashboard'),

    # User Management URLs
    path('admin/users/', views.user_list, name='user_list'),
    path('admin/users/add/', views.add_user, name='add_user'),
    path('admin/users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('admin/users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('admin/users/search/', views.search_users, name='search_users'),
    path('admin/users/<int:user_id>/permissions/', views.assign_permissions, name='assign_permissions'),
    path('admin/groups/create/', views.create_group, name='create_group'),
    path('admin/groups/', views.group_list, name='group_list'),
    path('admin/groups/<int:group_id>/edit/', views.edit_group, name='edit_group'),
    path('admin/groups/<int:group_id>/delete/', views.delete_group, name='delete_group'),
    path('admin/tickets/<int:ticket_id>/transfer/', views.transfer_ticket, name='transfer_ticket'),
    path('admin/priority/add/', views.add_priority, name='add_priority'),
    path("admin/priority/list/", views.priority_list, name="priority_list"),
    path('admin/support/email/', views.email_support_team, name='email_support_team'),
    path("admin/priority/delete/<int:priority_id>/", views.delete_priority, name="delete_priority"),
    path('admin/team/<int:team_id>/assign-view/', views.assign_team_view, name='assign_team_view'),

    # Settings URLs
    path('settings/', views.user_settings, name='user_settings'),
    path('admin/settings/', views.admin_settings, name='admin_settings'),
]