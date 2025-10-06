"""
Webhook notification system for eavesdropper detection alerts.
"""

import logging
import requests
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


def send_eavesdropper_detection_webhook(session, bb84_result):
    """
    Send webhook notification when eavesdropping is detected.
    
    Args:
        session: BB84Session instance with eavesdropper detection
        bb84_result: Dictionary with BB84 protocol results
    """
    # Get webhook URL from settings (configure in settings.py)
    webhook_url = getattr(settings, 'EAVESDROPPER_WEBHOOK_URL', None)
    
    if not webhook_url:
        logger.warning("EAVESDROPPER_WEBHOOK_URL not configured in settings - skipping webhook")
        return
    
    # Prepare webhook payload
    payload = {
        'event': 'eavesdropper_detected',
        'session_id': str(session.session_id),
        'sender': session.sender.email,
        'receiver': session.receiver.email,
        'qber': round(bb84_result['error_rate'], 4),
        'threshold': 0.15,  # Current threshold
        'detected_at': timezone.now().isoformat(),
        'eve_stats': {
            'bits_intercepted': bb84_result.get('num_intercepted', 0),
            'total_bits_transmitted': len(bb84_result['sender_bits']),
            'sifted_key_length': bb84_result['sifted_key_length'],
            'eavesdropper_probability': session.eavesdrop_probability,
        },
        'injected_by': session.eavesdropper_injected_by,
        'session_timeline': session.phase_timeline,
    }
    
    try:
        logger.info(f"Sending eavesdropper detection webhook to {webhook_url}")
        
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
            headers={
                'Content-Type': 'application/json',
                'X-Quantum-Alert': 'eavesdropper-detected',
                'X-Session-ID': str(session.session_id),
            }
        )
        
        if response.status_code in [200, 201, 202]:
            logger.info(f"Webhook sent successfully: {response.status_code}")
        else:
            logger.warning(f"Webhook returned non-success status: {response.status_code} - {response.text}")
            
    except requests.exceptions.Timeout:
        logger.error(f"Webhook request timed out: {webhook_url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Webhook request failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error sending webhook: {e}")


def test_webhook_endpoint(webhook_url):
    """
    Test webhook endpoint with a sample payload.
    
    Args:
        webhook_url: URL to test
        
    Returns:
        bool: True if webhook endpoint is reachable
    """
    test_payload = {
        'event': 'test',
        'message': 'Testing eavesdropper detection webhook',
        'timestamp': timezone.now().isoformat(),
    }
    
    try:
        response = requests.post(
            webhook_url,
            json=test_payload,
            timeout=5,
            headers={'Content-Type': 'application/json'}
        )
        
        logger.info(f"Webhook test: {response.status_code}")
        return response.status_code in [200, 201, 202]
        
    except Exception as e:
        logger.error(f"Webhook test failed: {e}")
        return False
