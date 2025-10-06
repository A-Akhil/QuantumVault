from django.contrib import admin
from .models import QuantumUser, EncryptedFile, FileAccess, AuditLog, UserGroup, BB84Session, OnlineStatus, ActiveEavesdropper


@admin.register(ActiveEavesdropper)
class ActiveEavesdropperAdmin(admin.ModelAdmin):
    list_display = ['eavesdropper_id', 'injected_by', 'is_active', 'intercept_probability', 'sessions_intercepted', 'detections_count', 'activated_at']
    list_filter = ['is_active', 'activated_at']
    search_fields = ['injected_by', 'eavesdropper_id']
    readonly_fields = ['eavesdropper_id', 'activated_at', 'deactivated_at', 'sessions_intercepted', 'total_qubits_intercepted', 'detections_count']
    
    fieldsets = (
        ('Eavesdropper Info', {
            'fields': ('eavesdropper_id', 'injected_by', 'is_active', 'intercept_probability')
        }),
        ('Statistics', {
            'fields': ('sessions_intercepted', 'total_qubits_intercepted', 'detections_count')
        }),
        ('Timestamps', {
            'fields': ('activated_at', 'deactivated_at')
        }),
    )


@admin.register(BB84Session)
class BB84SessionAdmin(admin.ModelAdmin):
    list_display = ['session_id', 'sender', 'receiver', 'status', 'receiver_accepted', 'error_rate', 'sifted_key_length', 'created_at']
    list_filter = ['status', 'receiver_accepted', 'eavesdropper_present', 'created_at']
    search_fields = ['sender__email', 'receiver__email', 'session_id']
    readonly_fields = ['session_id', 'created_at', 'updated_at', 'completed_at', 'accepted_at', 'phase_timeline']
    
    fieldsets = (
        ('Session Info', {
            'fields': ('session_id', 'sender', 'receiver', 'file', 'status', 'receiver_accepted', 'accepted_at')
        }),
        ('Timeline & Progress', {
            'fields': ('current_phase', 'progress_percentage', 'phase_timeline'),
            'classes': ('collapse',)
        }),
        ('BB84 Protocol Data', {
            'fields': ('error_rate', 'sifted_key_length', 'shared_key'),
            'classes': ('collapse',)
        }),
        ('Eavesdropper Simulation', {
            'fields': ('eavesdropper_present', 'eavesdrop_probability', 'num_intercepted', 'eavesdropper_injected_by'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'completed_at', 'expires_at')
        }),
    )


@admin.register(OnlineStatus)
class OnlineStatusAdmin(admin.ModelAdmin):
    list_display = ['user', 'is_online', 'last_heartbeat', 'last_seen']
    list_filter = ['is_online']
    search_fields = ['user__email', 'user__username']
    readonly_fields = ['last_heartbeat', 'last_seen']
