"""
BB84 Quantum Key Distribution utilities.

This module provides a classical simulation of the BB84 protocol suitable for
educational purposes and integration with the quantum-safe file storage system.
It includes utilities for generating random bit strings, encoding quantum states,
measuring qubits with optional eavesdropping simulation, error estimation, and
privacy amplification to derive a 256-bit shared secret.

The shared secret produced by BB84 is then used to wrap AES-256 keys for
encrypted file distribution.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

BASES = ['+', '×']  # Rectilinear and Diagonal bases
DEFAULT_KEY_LENGTH = 1024  # Initial bit length before sifting
DEFAULT_ERROR_THRESHOLD = 0.15  # 15% maximum acceptable QBER
DEFAULT_SAMPLE_SIZE = 50  # Number of bits to reveal during error estimation
TARGET_KEY_BYTES = 32  # 256-bit shared secret


class BB84Error(Exception):
    """Base exception for BB84 protocol operations."""


class EavesdroppingDetected(BB84Error):
    """Raised when the estimated error rate indicates eavesdropping."""


def generate_random_bits(length: int) -> List[int]:
    """Return a random list of bits of the desired length."""
    if length <= 0:
        raise ValueError("length must be positive")
    bits = [random.randint(0, 1) for _ in range(length)]
    logger.debug("Generated %d random bits", length)
    return bits


def generate_random_bases(length: int) -> List[str]:
    """Return a random list of measurement bases ('+' or '×')."""
    if length <= 0:
        raise ValueError("length must be positive")
    bases = [random.choice(BASES) for _ in range(length)]
    logger.debug("Generated %d random bases", length)
    return bases


def encode_quantum_state(bit: int, basis: str) -> Dict[str, object]:
    """Represent a classical bit encoded in the selected quantum basis."""
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    if basis not in BASES:
        raise ValueError("basis must be '+' or '×'")

    state_map = {
        (0, '+'): '|0⟩',
        (1, '+'): '|1⟩',
        (0, '×'): '|+⟩',
        (1, '×'): '|-⟩',
    }

    state = {
        'bit': bit,
        'basis': basis,
        'state': state_map[(bit, basis)],
    }
    logger.debug("Encoded bit=%d in basis=%s as state=%s", bit, basis, state['state'])
    return state


def encode_quantum_states(bits: List[int], bases: List[str]) -> List[Dict[str, object]]:
    """Encode a list of bits into simulated quantum states."""
    if len(bits) != len(bases):
        raise BB84Error("Bits and bases must be the same length")
    return [encode_quantum_state(bit, basis) for bit, basis in zip(bits, bases)]


def measure_quantum_state(state: Dict[str, object], measurement_basis: str) -> int:
    """Simulate measuring a quantum state in the specified basis."""
    if measurement_basis not in BASES:
        raise ValueError("measurement_basis must be '+' or '×'")

    original_basis = state['basis']
    original_bit = state['bit']

    if measurement_basis == original_basis:
        result = original_bit
    else:
        result = random.randint(0, 1)

    logger.debug(
        "Measured state=%s with basis=%s (original basis=%s) → %d",
        state['state'],
        measurement_basis,
        original_basis,
        result,
    )
    return result


def measure_quantum_states(states: List[Dict[str, object]], bases: List[str]) -> List[int]:
    """Measure a sequence of quantum states with corresponding bases."""
    if len(states) != len(bases):
        raise BB84Error("States and bases must be the same length")
    return [measure_quantum_state(state, basis) for state, basis in zip(states, bases)]


def simulate_eavesdropper(
    states: List[Dict[str, object]],
    intercept_probability: float = 0.0,
) -> Tuple[List[Dict[str, object]], int]:
    """
    Simulate Eve intercepting and re-transmitting a subset of qubits.

    Args:
        states: Original quantum states emitted by the sender.
        intercept_probability: Probability that Eve intercepts each state.

    Returns:
        A tuple of (modified_states, intercepted_count).
    """
    if not 0.0 <= intercept_probability <= 1.0:
        raise ValueError("intercept_probability must be between 0 and 1")

    modified_states: List[Dict[str, object]] = []
    intercepted = 0

    for state in states:
        if random.random() < intercept_probability:
            intercepted += 1
            eve_basis = random.choice(BASES)
            measurement = measure_quantum_state(state, eve_basis)
            modified_state = encode_quantum_state(measurement, eve_basis)
            modified_states.append(modified_state)
            logger.debug(
                "Eve intercepted state=%s using basis=%s and resent %s",
                state['state'],
                eve_basis,
                modified_state['state'],
            )
        else:
            modified_states.append(state)

    logger.info("Eve intercepted %d/%d qubits", intercepted, len(states))
    return modified_states, intercepted


def sift_key(
    sender_bits: List[int],
    sender_bases: List[str],
    receiver_bits: List[int],
    receiver_bases: List[str],
) -> Tuple[List[int], List[int]]:
    """Keep only the bits where sender and receiver used matching bases."""
    if not (len(sender_bits) == len(sender_bases) == len(receiver_bits) == len(receiver_bases)):
        raise BB84Error("All BB84 arrays must be the same length")

    sifted_bits: List[int] = []
    matched_indices: List[int] = []

    for index, (s_bit, s_basis, r_bit, r_basis) in enumerate(
        zip(sender_bits, sender_bases, receiver_bits, receiver_bases)
    ):
        if s_basis == r_basis:
            sifted_bits.append(r_bit)
            matched_indices.append(index)

    logger.info("Sifted %d bits from %d transmitted", len(sifted_bits), len(sender_bits))
    return sifted_bits, matched_indices


def estimate_error_rate(
    sender_sifted_bits: List[int],
    receiver_sifted_bits: List[int],
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> Tuple[float, List[int]]:
    """Estimate the quantum bit error rate (QBER)."""
    if len(sender_sifted_bits) != len(receiver_sifted_bits):
        raise BB84Error("Sifted bit arrays must match in size")

    if not sender_sifted_bits:
        raise BB84Error("Cannot estimate error rate from empty sifted key")

    size = min(sample_size, len(sender_sifted_bits))
    sampled_indices = random.sample(range(len(sender_sifted_bits)), size)

    errors = sum(
        1 for idx in sampled_indices if sender_sifted_bits[idx] != receiver_sifted_bits[idx]
    )
    error_rate = errors / size

    logger.info("Estimated error rate %.2f%% (%d/%d errors)", error_rate * 100, errors, size)
    return error_rate, sampled_indices


def privacy_amplification(
    sifted_bits: List[int],
    sampled_indices: List[int],
    target_key_bytes: int = TARGET_KEY_BYTES,
) -> bytes:
    """
    Apply privacy amplification by removing sampled bits and hashing the rest.
    """
    if target_key_bytes <= 0:
        raise ValueError("target_key_bytes must be positive")

    remaining_bits = [bit for idx, bit in enumerate(sifted_bits) if idx not in sampled_indices]
    if len(remaining_bits) < target_key_bytes * 8:
        raise BB84Error(
            "Not enough bits after sampling for privacy amplification: have "
            f"{len(remaining_bits)}, need {target_key_bytes * 8}"
        )

    bit_string = ''.join(str(bit) for bit in remaining_bits)
    bit_bytes = int(bit_string, 2).to_bytes((len(bit_string) + 7) // 8, byteorder='big')
    digest = hashlib.sha256(bit_bytes).digest()

    logger.info(
        "Privacy amplification reduced %d bits to %d-byte key",
        len(remaining_bits),
        target_key_bytes,
    )
    return digest[:target_key_bytes]


def run_bb84_protocol(
    key_length: int = DEFAULT_KEY_LENGTH,
    *,
    eavesdropper_present: bool = False,
    eavesdrop_probability: float = 0.0,
    error_threshold: float = DEFAULT_ERROR_THRESHOLD,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> Dict[str, object]:
    """
    Execute the full BB84 protocol and return a dictionary with results.

    Raises:
        EavesdroppingDetected: If the measured error rate exceeds the threshold.
    """
    if key_length <= 0:
        raise ValueError("key_length must be positive")

    logger.info(
        "Running BB84 protocol (length=%d, eve=%s, intercept=%.2f)",
        key_length,
        eavesdropper_present,
        eavesdrop_probability,
    )

    sender_bits = generate_random_bits(key_length)
    sender_bases = generate_random_bases(key_length)
    states = encode_quantum_states(sender_bits, sender_bases)

    intercepted = 0
    if eavesdropper_present and eavesdrop_probability > 0.0:
        states, intercepted = simulate_eavesdropper(states, eavesdrop_probability)

    receiver_bases = generate_random_bases(key_length)
    receiver_measurements = measure_quantum_states(states, receiver_bases)

    sifted_bits, matched_indices = sift_key(
        sender_bits,
        sender_bases,
        receiver_measurements,
        receiver_bases,
    )
    receiver_sifted_bits = [receiver_measurements[idx] for idx in matched_indices]
    sender_sifted_bits = [sender_bits[idx] for idx in matched_indices]

    error_rate, sampled_indices = estimate_error_rate(
        sender_sifted_bits,
        receiver_sifted_bits,
        sample_size=sample_size,
    )

    if error_rate > error_threshold:
        logger.error(
            "Eavesdropping detected: error rate %.2f%% exceeds threshold %.2f%%",
            error_rate * 100,
            error_threshold * 100,
        )
        raise EavesdroppingDetected(
            f"Measured error rate {error_rate:.2%} exceeds threshold {error_threshold:.2%}"
        )

    shared_key = privacy_amplification(
        receiver_sifted_bits,
        sampled_indices,
        target_key_bytes=TARGET_KEY_BYTES,
    )

    result = {
        'success': True,
        'sender_bits': sender_bits,
        'sender_bases': sender_bases,
        'receiver_bases': receiver_bases,
        'receiver_measurements': receiver_measurements,
        'matched_indices': matched_indices,
        'sifted_key_length': len(sifted_bits),
        'error_rate': error_rate,
        'eavesdropper_present': eavesdropper_present,
        'num_intercepted': intercepted,
        'shared_key': shared_key,
        'sampled_indices': sampled_indices,
    }
    logger.info("BB84 protocol completed successfully; shared key length=%d bytes", len(shared_key))
    return result


def run_bb84_protocol_with_timeline(
    session,
    key_length: int = DEFAULT_KEY_LENGTH,
    *,
    eavesdropper_present: bool = False,
    eavesdrop_probability: float = 0.0,
    error_threshold: float = DEFAULT_ERROR_THRESHOLD,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> Dict[str, object]:
    """
    Execute BB84 protocol with 10+ second timeline for educational visualization.
    Updates session.current_phase and progress_percentage as it progresses.
    
    Timeline (minimum 10 seconds):
    - Phase 1: Quantum state preparation (2s) - 10-30%
    - Phase 2: Quantum transmission (5s) - 30-60%
    - Phase 3: Basis comparison (2s) - 60-75%
    - Phase 4: Error rate estimation (2s) - 75-90%
    - Phase 5: Privacy amplification (1s) - 90-100%
    
    Args:
        session: BB84Session model instance to update
        Other args same as run_bb84_protocol
    
    Returns:
        Same as run_bb84_protocol
    
    Raises:
        EavesdroppingDetected: If error rate exceeds threshold
    """
    import time
    from django.utils import timezone
    
    if key_length <= 0:
        raise ValueError("key_length must be positive")
    
    timeline = []
    
    logger.info(
        "Running BB84 protocol WITH TIMELINE (length=%d, eve=%s, intercept=%.2f)",
        key_length,
        eavesdropper_present,
        eavesdrop_probability,
    )
    
    # PHASE 1: Quantum State Preparation (2 seconds)
    session.current_phase = "Phase 1: Preparing quantum states..."
    session.progress_percentage = 10
    session.save()
    timeline.append({'phase': 'preparation', 'timestamp': timezone.now().isoformat(), 'progress': 10})
    
    sender_bits = generate_random_bits(key_length)
    sender_bases = generate_random_bases(key_length)
    time.sleep(1)  # Simulate preparation time
    
    session.current_phase = "Phase 1: Encoding quantum states..."
    session.progress_percentage = 20
    session.save()
    timeline.append({'phase': 'encoding', 'timestamp': timezone.now().isoformat(), 'progress': 20})
    
    states = encode_quantum_states(sender_bits, sender_bases)
    time.sleep(1)
    
    session.progress_percentage = 30
    session.save()
    
    # PHASE 2: Quantum Transmission (5 seconds) - Eve can intercept here
    session.current_phase = "Phase 2: Transmitting quantum states over channel..."
    session.progress_percentage = 35
    session.save()
    timeline.append({'phase': 'transmission_start', 'timestamp': timezone.now().isoformat(), 'progress': 35})
    
    time.sleep(2)
    session.progress_percentage = 45
    session.save()
    
    # Eavesdropper intercepts during transmission
    intercepted = 0
    if eavesdropper_present and eavesdrop_probability > 0.0:
        session.current_phase = "Phase 2: ⚠️ Eavesdropper intercepting qubits..."
        session.save()
        timeline.append({'phase': 'eavesdropper_active', 'timestamp': timezone.now().isoformat(), 'progress': 45})
        states, intercepted = simulate_eavesdropper(states, eavesdrop_probability)
    
    time.sleep(2)
    session.progress_percentage = 55
    session.save()
    
    session.current_phase = "Phase 2: Receiver measuring quantum states..."
    session.save()
    timeline.append({'phase': 'measurement', 'timestamp': timezone.now().isoformat(), 'progress': 55})
    
    receiver_bases = generate_random_bases(key_length)
    receiver_measurements = measure_quantum_states(states, receiver_bases)
    time.sleep(1)
    
    session.progress_percentage = 60
    session.save()
    
    # PHASE 3: Basis Reconciliation / Sifting (2 seconds)
    session.current_phase = "Phase 3: Comparing measurement bases..."
    session.progress_percentage = 65
    session.save()
    timeline.append({'phase': 'basis_comparison', 'timestamp': timezone.now().isoformat(), 'progress': 65})
    
    time.sleep(1)
    
    sifted_bits, matched_indices = sift_key(
        sender_bits,
        sender_bases,
        receiver_measurements,
        receiver_bases,
    )
    receiver_sifted_bits = [receiver_measurements[idx] for idx in matched_indices]
    sender_sifted_bits = [sender_bits[idx] for idx in matched_indices]
    
    session.current_phase = f"Phase 3: Sifted {len(sifted_bits)} matching bits..."
    session.progress_percentage = 75
    session.save()
    timeline.append({'phase': 'sifting_complete', 'timestamp': timezone.now().isoformat(), 'progress': 75, 'sifted_bits': len(sifted_bits)})
    
    time.sleep(1)
    
    # PHASE 4: Error Rate Estimation (2 seconds)
    session.current_phase = "Phase 4: Estimating quantum bit error rate (QBER)..."
    session.progress_percentage = 80
    session.save()
    timeline.append({'phase': 'error_estimation', 'timestamp': timezone.now().isoformat(), 'progress': 80})
    
    time.sleep(1)
    
    error_rate, sampled_indices = estimate_error_rate(
        sender_sifted_bits,
        receiver_sifted_bits,
        sample_size=sample_size,
    )
    
    session.current_phase = f"Phase 4: QBER = {error_rate*100:.2f}% (threshold: {error_threshold*100:.0f}%)"
    session.progress_percentage = 85
    session.save()
    timeline.append({'phase': 'error_rate_computed', 'timestamp': timezone.now().isoformat(), 'progress': 85, 'error_rate': error_rate})
    
    time.sleep(1)
    
    # Check for eavesdropping detection
    if error_rate > error_threshold:
        session.current_phase = f"❌ EAVESDROPPING DETECTED! QBER {error_rate*100:.2f}% > {error_threshold*100:.0f}%"
        session.progress_percentage = 90
        session.phase_timeline = timeline
        session.save()
        timeline.append({'phase': 'eavesdropper_detected', 'timestamp': timezone.now().isoformat(), 'progress': 90, 'error_rate': error_rate})
        
        logger.error(
            "Eavesdropping detected: error rate %.2f%% exceeds threshold %.2f%%",
            error_rate * 100,
            error_threshold * 100,
        )
        raise EavesdroppingDetected(
            f"Measured error rate {error_rate:.2%} exceeds threshold {error_threshold:.2%}"
        )
    
    # PHASE 5: Privacy Amplification (1 second)
    session.current_phase = "Phase 5: Privacy amplification (hashing to 256-bit key)..."
    session.progress_percentage = 90
    session.save()
    timeline.append({'phase': 'privacy_amplification', 'timestamp': timezone.now().isoformat(), 'progress': 90})
    
    time.sleep(1)
    
    shared_key = privacy_amplification(
        receiver_sifted_bits,
        sampled_indices,
        target_key_bytes=TARGET_KEY_BYTES,
    )
    
    session.current_phase = "✅ Shared key established successfully!"
    session.progress_percentage = 100
    timeline.append({'phase': 'completed', 'timestamp': timezone.now().isoformat(), 'progress': 100})
    session.phase_timeline = timeline
    session.save()
    
    result = {
        'success': True,
        'sender_bits': sender_bits,
        'sender_bases': sender_bases,
        'receiver_bases': receiver_bases,
        'receiver_measurements': receiver_measurements,
        'matched_indices': matched_indices,
        'sifted_key_length': len(sifted_bits),
        'error_rate': error_rate,
        'eavesdropper_present': eavesdropper_present,
        'num_intercepted': intercepted,
        'shared_key': shared_key,
        'sampled_indices': sampled_indices,
        'timeline': timeline,
    }
    
    logger.info("BB84 protocol with timeline completed successfully; shared key length=%d bytes", len(shared_key))
    return result


def wrap_aes_key_with_bb84_key(master_aes_key: bytes, bb84_shared_key: bytes) -> Tuple[bytes, bytes]:
    """Encrypt an AES key using a BB84-derived shared secret."""
    if len(bb84_shared_key) != TARGET_KEY_BYTES:
        raise ValueError("bb84_shared_key must be 32 bytes (256 bits)")
    if len(master_aes_key) != TARGET_KEY_BYTES:
        raise ValueError("master_aes_key must be 32 bytes (AES-256)")

    nonce = os.urandom(12)
    aesgcm = AESGCM(bb84_shared_key)
    wrapped_key = aesgcm.encrypt(nonce, master_aes_key, None)
    logger.debug("Wrapped AES key (%d bytes ciphertext)", len(wrapped_key))
    return wrapped_key, nonce


def unwrap_aes_key_with_bb84_key(
    wrapped_key: bytes,
    nonce: bytes,
    bb84_shared_key: bytes,
) -> bytes:
    """Decrypt an AES key using a BB84-derived shared secret."""
    if len(bb84_shared_key) != TARGET_KEY_BYTES:
        raise ValueError("bb84_shared_key must be 32 bytes (256 bits)")

    aesgcm = AESGCM(bb84_shared_key)
    master_aes_key = aesgcm.decrypt(nonce, wrapped_key, None)
    if len(master_aes_key) != TARGET_KEY_BYTES:
        raise BB84Error("Decrypted AES key has unexpected length")

    logger.debug("Unwrapped AES key successfully")
    return master_aes_key


def demo_bb84_protocol() -> None:
    """Convenience function to print BB84 execution results to stdout."""
    print("=" * 60)
    print("BB84 Protocol Demonstration")
    print("=" * 60)

    try:
        result = run_bb84_protocol()
        print("[Normal] Shared key (hex):", result['shared_key'].hex())
        print("          Error rate: {:.2%}".format(result['error_rate']))
    except Exception as exc:
        print("[Normal] Protocol failed:", exc)

    try:
        run_bb84_protocol(
            eavesdropper_present=True,
            eavesdrop_probability=0.4,
        )
        print("[Eavesdropper] Unexpected success")
    except EavesdroppingDetected as exc:
        print("[Eavesdropper] Detection triggered:", exc)

    print("=" * 60)
