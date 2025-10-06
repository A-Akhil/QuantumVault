# BB84 Educational Demo - Testing Guide

## Overview
This guide walks through testing the complete BB84 quantum key exchange demonstration system with external eavesdropper injection.

---

## Prerequisites

1. **Start Django Server:**
   ```bash
   python manage.py runserver
   ```

2. **Create Test Users:**
   - User A (Sender): alice@example.com
   - User B (Receiver): bob@example.com
   - Login credentials set during user creation

---

## Test Scenario 1: Normal BB84 (No Eavesdropper)

**Goal:** Verify proper handshake flow and successful key exchange without interference.

### Steps:

1. **Login as Alice (Sender)**
   - Navigate to: http://localhost:8000/key-exchange/initiate/
   - Select recipient: Bob (bob@example.com)
   - Click "Initiate BB84 Key Exchange Request"
   - ✅ Expected: Session created with status='pending'

2. **Login as Bob (Receiver)**
   - Navigate to: http://localhost:8000/key-exchange/sessions/
   - See pending session from Alice in "Pending Requests" table
   - Click "Accept" button
   - ✅ Expected: Timeline modal opens

3. **Watch BB84 Protocol Execution (10-15 seconds)**
   - Progress bar advances from 0% → 100%
   - 5 phases display in sequence:
     - ⚙️ Preparation (10-30%)
     - ↔️ Transmission (30-60%)
     - 🔧 Sifting (60-75%)
     - 🛡️ Error Checking (75-90%)
     - ✅ Privacy Amplification (90-100%)
   - Each phase shows timestamp
   - ✅ Expected: 
     - QBER: ~0-5% (very low)
     - Status: "Completed" with green badge
     - Eavesdropper: "No" indicator

4. **Verify Results**
   - Session status = 'completed'
   - Shared key generated
   - Low error rate confirms secure channel

---

## Test Scenario 2: Eavesdropper Injection & Detection

**Goal:** Inject Eve externally and verify automatic interception and detection.

### Steps:

#### Part A: Inject Eavesdropper

```bash
# Inject eavesdropper with 50% interception probability
curl -X POST http://localhost:8000/api/eavesdropper/inject/ \
  -H "Content-Type: application/json" \
  -d '{
    "injected_by": "demo_script",
    "intercept_probability": 0.5
  }'
```

**Expected Response:**
```json
{
  "success": true,
  "eavesdropper_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Eavesdropper injected successfully"
}
```

#### Part B: View Eavesdropper Dashboard

- Navigate to: http://localhost:8000/eavesdropper/dashboard/
- ✅ Expected to see:
  - Red alert card: "Eavesdropper Active"
  - Eve ID (UUID)
  - Injected by: "demo_script"
  - Intercept probability: 0.50 (50%)
  - Statistics: sessions=0, qubits=0, detections=0

#### Part C: Run BB84 with Active Eavesdropper

1. **Repeat Scenario 1 steps** (Alice initiates → Bob accepts)

2. **During Transmission Phase:**
   - Modal shows: **"⚠️ Eavesdropper Active"** indicator
   - Eve intercepts ~50% of qubits (configured probability)
   - Timeline updates continue

3. **At Error Checking Phase:**
   - QBER calculated: ~20-30% (high!)
   - Threshold check: 15%
   - ✅ Expected: **QBER > 15% → DETECTION!**

4. **Session Fails:**
   - Status: "failed" with red badge
   - Error message: "Eavesdropping detected! QBER 24.5% exceeds threshold 15%"
   - No key generated
   - Session aborted

5. **Webhook Notification** (if configured):
   ```json
   POST https://your-endpoint.com/webhook
   {
     "event": "eavesdropper_detected",
     "session_id": "abc123",
     "sender": "alice@example.com",
     "receiver": "bob@example.com",
     "qber": 0.245,
     "threshold": 0.15,
     "timestamp": "2024-12-11T10:45:30Z",
     "eve_stats": {
       "bits_intercepted": 512,
       "total_bits_transmitted": 1024,
       "sifted_key_length": 256
     }
   }
   ```

6. **Dashboard Updates:**
   - Sessions intercepted: +1
   - Total qubits intercepted: +512
   - Detections count: +1
   - Recent interceptions table shows new entry

---

## Test Scenario 3: Multiple Sessions with Active Eve

**Goal:** Verify Eve intercepts ALL sessions while active.

### Steps:

1. **Ensure Eavesdropper Active** (from Scenario 2)

2. **Create 3 BB84 Sessions:**
   - Alice → Bob
   - Alice → Charlie
   - Bob → Charlie

3. **All sessions accept simultaneously**

4. **Watch Dashboard:**
   - "Active Quantum Transmissions" table shows all 3
   - Each row shows progress percentage
   - All marked with red "Intercepted: YES" badge

5. **After All Complete:**
   - Statistics updated:
     - sessions_intercepted: 3
     - detections_count: 2-3 (depends on QBER)
   - Recent interceptions table shows all 3

---

## Test Scenario 4: Deactivate Eavesdropper

**Goal:** Remove Eve and verify normal operation resumes.

### Steps:

1. **Deactivate via Dashboard:**
   - Go to: http://localhost:8000/eavesdropper/dashboard/
   - Click "Deactivate Eavesdropper" button
   - Confirm dialog
   - ✅ Expected: Blue info alert "No active eavesdropper"

2. **OR Deactivate via API:**
   ```bash
   curl -X POST http://localhost:8000/api/eavesdropper/deactivate/
   ```
   
   **Response:**
   ```json
   {
     "success": true,
     "message": "Eavesdropper deactivated successfully"
   }
   ```

3. **Run New BB84 Session:**
   - Alice → Bob
   - ✅ Expected: Normal flow (Scenario 1)
   - No eavesdropper indicator
   - Low QBER
   - Successful completion

---

## Test Scenario 5: Singleton Enforcement

**Goal:** Verify only ONE eavesdropper can be active at a time.

### Steps:

1. **Inject First Eavesdropper:**
   ```bash
   curl -X POST http://localhost:8000/api/eavesdropper/inject/ \
     -H "Content-Type: application/json" \
     -d '{"injected_by": "eve_1", "intercept_probability": 0.3}'
   ```

2. **Check Status:**
   ```bash
   curl http://localhost:8000/api/eavesdropper/status/
   ```
   
   **Response shows:** eve_1 active

3. **Inject Second Eavesdropper:**
   ```bash
   curl -X POST http://localhost:8000/api/eavesdropper/inject/ \
     -H "Content-Type: application/json" \
     -d '{"injected_by": "eve_2", "intercept_probability": 0.7}'
   ```

4. **Verify Singleton Behavior:**
   ```bash
   curl http://localhost:8000/api/eavesdropper/status/
   ```
   
   ✅ Expected: Only eve_2 active (eve_1 automatically deactivated)

---

## API Reference

### 1. Inject Eavesdropper
```bash
POST /api/eavesdropper/inject/
Content-Type: application/json

{
  "injected_by": "script_name",
  "intercept_probability": 0.5  # Range: 0.0 - 1.0
}
```

### 2. Deactivate Eavesdropper
```bash
POST /api/eavesdropper/deactivate/
```

### 3. Check Status
```bash
GET /api/eavesdropper/status/
```

### 4. View Dashboard
```
GET /eavesdropper/dashboard/
```

---

## Troubleshooting

### Issue: Session Stuck in "Transmitting" Phase
**Solution:** Check server logs for errors. BB84 runs in background thread - verify no exceptions.

### Issue: Dashboard Not Updating
**Solution:** Dashboard auto-refreshes every 5 seconds. Force refresh (Ctrl+F5) if needed.

### Issue: Webhook Not Firing
**Solution:** 
1. Check `settings.py`: `EAVESDROPPER_WEBHOOK_URL` configured?
2. Verify webhook endpoint is reachable
3. Check server logs for webhook errors

### Issue: "No Active Eavesdropper" but API Says Active
**Solution:** Clear browser cache or check database directly:
```bash
python manage.py shell
>>> from core.models import ActiveEavesdropper
>>> ActiveEavesdropper.objects.filter(is_active=True).count()
```

---

## Success Criteria Checklist

- [ ] Pending sessions require receiver acceptance (no instant key gen)
- [ ] BB84 protocol takes 10-15 seconds to complete
- [ ] Timeline shows all 5 phases with timestamps
- [ ] Eavesdropper cannot be controlled via UI
- [ ] API injection creates active eavesdropper
- [ ] Only ONE eavesdropper active at any time
- [ ] Active Eve intercepts ALL subsequent sessions
- [ ] QBER > 15% triggers detection
- [ ] Webhook fires on detection (if configured)
- [ ] Dashboard shows real-time session list
- [ ] Statistics update after each interception
- [ ] Deactivation stops future interceptions

---

## Next Steps

1. **Automated Testing:** Write pytest test cases for all scenarios
2. **Documentation:** Update main README.md with workflow diagrams
3. **Monitoring:** Add logging for all eavesdropper events
4. **Security:** Add authentication to API endpoints (currently CSRF-exempt)

---

**System Status:** ✅ Fully Functional Educational BB84 Demo
