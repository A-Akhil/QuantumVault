"""
URL configuration for core app.
"""

from django.urls import path
from . import views
from . import api_views
from . import eavesdropper_api

urlpatterns = [
    # Authentication URLs
    path('', views.home_view, name='home'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Dashboard and file management
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('my-files/', views.my_files_view, name='my_files'),
    path('shared-with-me/', views.shared_with_me_view, name='shared_with_me'),
    path('upload/', views.upload_file_view, name='upload'),
    path('download/<int:file_id>/', views.download_file_view, name='download_file'),
    path('files/<int:file_id>/share/', views.manage_file_sharing_view, name='manage_file_sharing'),
    path('files/<int:file_id>/access/add/', views.add_file_access_view, name='add_file_access'),
    path('files/<int:file_id>/access/remove/', views.remove_file_access_view, name='remove_file_access'),
    path('files/<int:file_id>/delete/', views.delete_file_view, name='delete_file'),
    
    # BB84 Quantum Key Exchange
    path('key-exchange/', views.key_exchange_view, name='key_exchange'),
    path('key-exchange/initiate/', views.initiate_key_exchange_view, name='initiate_key_exchange'),
    path('key-exchange/sessions/', views.bb84_sessions_view, name='bb84_sessions'),
    path('key-exchange/accept/<uuid:session_id>/', views.accept_bb84_session_view, name='accept_bb84_session'),
    path('key-exchange/status/<uuid:session_id>/', views.bb84_session_status_view, name='bb84_session_status'),
    
    # Audit and monitoring
    path('audit/', views.audit_logs_view, name='audit_logs'),
    
    # Group management
    path('groups/', views.manage_groups_view, name='manage_groups'),
    path('groups/create/', views.create_group_view, name='create_group'),
    path('groups/<int:group_id>/edit/', views.edit_group_view, name='edit_group'),
    path('groups/<int:group_id>/delete/', views.delete_group_view, name='delete_group'),
    
    # API endpoints for backend testing
    path('api/status/', api_views.api_status, name='api_status'),
    path('api/register/', api_views.api_register, name='api_register'),
    path('api/login/', api_views.api_login, name='api_login'),
    path('api/upload/', api_views.api_upload_file, name='api_upload'),
    path('api/files/', api_views.api_list_files, name='api_list_files'),
    path('api/download/<int:file_id>/', api_views.api_download_file, name='api_download'),
    path('api/audit/', api_views.api_audit_logs, name='api_audit'),
    
    # Eavesdropper API endpoints (external injection)
    path('api/eavesdropper/inject/', eavesdropper_api.inject_eavesdropper_api, name='api_inject_eavesdropper'),
    path('api/eavesdropper/deactivate/', eavesdropper_api.deactivate_eavesdropper_api, name='api_deactivate_eavesdropper'),
    path('api/eavesdropper/status/', eavesdropper_api.eavesdropper_status_api, name='api_eavesdropper_status'),
    path('eavesdropper/dashboard/', eavesdropper_api.eavesdropper_dashboard_view, name='eavesdropper_dashboard'),
]