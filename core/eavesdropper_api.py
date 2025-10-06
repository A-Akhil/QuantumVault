"""
API endpoints for external eavesdropper injection.
Allows external scripts to inject eavesdroppers into BB84 sessions.
"""

import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from core.models import ActiveEavesdropper, BB84Session
import json

logger = logging.getLogger(__name__)


@csrf_exempt
@require_http_methods(["POST"])
def inject_eavesdropper_api(request):
    """
    API endpoint to inject an eavesdropper into the system.
    Only ONE eavesdropper can be active at a time (system-wide).
    
    POST /api/eavesdropper/inject/
    Body: {
        "injected_by": "script_name or email",
        "intercept_probability": 0.0-1.0 (default: 0.5)
    }
    
    Returns: {
        "success": true,
        "eavesdropper_id": "uuid",
        "message": "Eavesdropper injected successfully"
    }
    """
    try:
        data = json.loads(request.body)
        injected_by = data.get('injected_by', 'unknown')
        intercept_probability = float(data.get('intercept_probability', 0.5))
        
        # Validate probability
        if not 0.0 <= intercept_probability <= 1.0:
            return JsonResponse({
                'success': False,
                'error': 'intercept_probability must be between 0.0 and 1.0'
            }, status=400)
        
        # Check if there's already an active eavesdropper
        existing_eve = ActiveEavesdropper.get_active()
        if existing_eve:
            # Deactivate existing one
            existing_eve.deactivate()
            logger.info(f"Deactivated existing eavesdropper {existing_eve.eavesdropper_id}")
        
        # Create new eavesdropper
        eve = ActiveEavesdropper.objects.create(
            injected_by=injected_by,
            intercept_probability=intercept_probability,
            is_active=True
        )
        
        logger.info(
            f"Eavesdropper {eve.eavesdropper_id} injected by {injected_by} "
            f"with probability {intercept_probability}"
        )
        
        # Count active sessions that will be affected
        active_sessions = BB84Session.objects.filter(
            status__in=['accepted', 'transmitting', 'sifting']
        ).count()
        
        return JsonResponse({
            'success': True,
            'eavesdropper_id': str(eve.eavesdropper_id),
            'intercept_probability': intercept_probability,
            'injected_by': injected_by,
            'active_sessions_to_intercept': active_sessions,
            'message': 'Eavesdropper injected successfully. Will intercept new BB84 sessions.'
        }, status=201)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON in request body'
        }, status=400)
    except Exception as e:
        logger.error(f"Error injecting eavesdropper: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def deactivate_eavesdropper_api(request):
    """
    API endpoint to deactivate the current active eavesdropper.
    
    POST /api/eavesdropper/deactivate/
    
    Returns: {
        "success": true,
        "message": "Eavesdropper deactivated"
    }
    """
    try:
        eve = ActiveEavesdropper.get_active()
        
        if not eve:
            return JsonResponse({
                'success': False,
                'message': 'No active eavesdropper found'
            }, status=404)
        
        eve.deactivate()
        
        logger.info(f"Eavesdropper {eve.eavesdropper_id} deactivated")
        
        return JsonResponse({
            'success': True,
            'eavesdropper_id': str(eve.eavesdropper_id),
            'sessions_intercepted': eve.sessions_intercepted,
            'detections_count': eve.detections_count,
            'message': 'Eavesdropper deactivated successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deactivating eavesdropper: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def eavesdropper_status_api(request):
    """
    API endpoint to get current eavesdropper status.
    
    GET /api/eavesdropper/status/
    
    Returns: {
        "active": true/false,
        "eavesdropper_id": "uuid" or null,
        "details": {...}
    }
    """
    try:
        eve = ActiveEavesdropper.get_active()
        
        if not eve:
            return JsonResponse({
                'active': False,
                'eavesdropper_id': None,
                'message': 'No active eavesdropper'
            })
        
        # Count ongoing sessions
        ongoing_sessions = BB84Session.objects.filter(
            status__in=['accepted', 'transmitting', 'sifting'],
            eavesdropper_present=True
        ).count()
        
        return JsonResponse({
            'active': True,
            'eavesdropper_id': str(eve.eavesdropper_id),
            'injected_by': eve.injected_by,
            'intercept_probability': eve.intercept_probability,
            'sessions_intercepted': eve.sessions_intercepted,
            'total_qubits_intercepted': eve.total_qubits_intercepted,
            'detections_count': eve.detections_count,
            'ongoing_sessions': ongoing_sessions,
            'activated_at': eve.activated_at.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting eavesdropper status: {e}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
def eavesdropper_dashboard_view(request):
    """
    Dashboard view showing all active BB84 sessions and eavesdropper status.
    For Eve to monitor what transmissions are happening.
    """
    active_eavesdropper = ActiveEavesdropper.get_active()
    
    # Get all sessions currently in transmission/active phases
    active_sessions = BB84Session.objects.filter(
        status__in=['accepted', 'transmitting', 'sifting', 'checking']
    ).order_by('-created_at')[:10]
    
    # Get recently intercepted sessions (completed or failed with eavesdropper)
    recent_intercepted = BB84Session.objects.filter(
        eavesdropper_present=True,
        status__in=['completed', 'failed']
    ).order_by('-completed_at')[:20]
    
    context = {
        'active_eavesdropper': active_eavesdropper,
        'active_sessions': active_sessions,
        'recent_intercepted': recent_intercepted,
    }
    
    return render(request, 'core/eavesdropper_dashboard.html', context)
