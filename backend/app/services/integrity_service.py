import hashlib
import hmac
import base64
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def serialize_value(v: Any) -> str:
    """Deterministically serialize values for cryptographic hashing."""
    if isinstance(v, datetime):
        # Normalize to ISO 8601 UTC
        if v.tzinfo is None:
            return v.isoformat() + "+00:00"
        return v.astimezone(timezone.utc).isoformat()
    if isinstance(v, float):
        return f"{v:.6f}".rstrip('0').rstrip('.')
    if v is None:
        return "None"
    return str(v)

def _get_hmac_key() -> Optional[bytes]:
    """Retrieves the HMAC secret key from the environment."""
    from app.config import settings
    key = settings.EVIDENCE_HMAC_KEY or os.environ.get("EVIDENCE_HMAC_KEY")
    if not key:
        return None
    return key.encode('utf-8')

def _get_canonical_string(record_type: str, target: Any) -> str:
    """Extracts fields and creates the deterministic canonical string."""
    fields = []
    
    if record_type == "SuricataEvent":
        fields = [
            target.id, 
            target.session_id, 
            target.timestamp, 
            target.raw_signature, 
            target.src_ip, 
            target.dest_ip, 
            target.dest_port, 
            target.protocol, 
            target.severity,
            getattr(target, 'previous_hash', None)
        ]
        
    elif record_type == "Detection":
        source_val = target.source.value if hasattr(target.source, 'value') else str(target.source)
        fields = [
            target.id, 
            target.session_id, 
            target.timestamp, 
            source_val, 
            target.label, 
            target.confidence, 
            target.features,
            getattr(target, 'previous_hash', None)
        ]
        
    elif record_type == "SecurityEvent":
        payload_str = target.payload_json
        if payload_str and isinstance(payload_str, str):
            try:
                # Canonicalize JSON by sorting keys and removing extraneous whitespace
                parsed = json.loads(payload_str)
                payload_str = json.dumps(parsed, sort_keys=True, separators=(',', ':'))
            except Exception:
                pass
                
        fields = [
            target.id, 
            target.session_id, 
            target.timestamp, 
            target.simulation_id, 
            target.scenario, 
            target.event_type, 
            target.source, 
            target.target, 
            payload_str,
            getattr(target, 'previous_hash', None)
        ]
    else:
        return ""
        
    return "|".join(serialize_value(f) for f in fields)

def canonicalize_and_hash(record_type: str, target: Any) -> Optional[str]:
    """
    Computes a deterministic HMAC-SHA-256 MAC covering the stable identity (ID),
    timestamp, and critical payload fields of the specified record type.
    """
    canonical_string = _get_canonical_string(record_type, target)
    if not canonical_string:
        return None
        
    key = _get_hmac_key()
    if not key:
        raise ValueError("Evidence signing failed: Cryptographic key material is unavailable.")
        
    mac = hmac.new(key, canonical_string.encode('utf-8'), hashlib.sha256).digest()
    encoded_mac = base64.b64encode(mac).decode('ascii')
    return f"v2:{encoded_mac}"

def verify_record_integrity(record_type: str, record: Any, db_session: Any = None) -> str:
    """
    Recomputes the hash of a persisted record and compares it to the stored hash.
    If db_session is provided and the record has a previous_hash, it verifies the chain.
    Returns: 'verified', 'verified_legacy', 'mismatch', 'missing_hash', 'chain_broken', or 'verification_unavailable'.
    """
    try:
        stored_hash = getattr(record, 'evidence_hash', None)
        if not stored_hash:
            return "missing_hash"
            
        canonical_string = _get_canonical_string(record_type, record)
        if not canonical_string:
            return "verification_unavailable"
            
        # First verify the HMAC of the current record
        record_verified = False
        is_legacy = False
        
        if stored_hash.startswith("v2:"):
            key = _get_hmac_key()
            if not key:
                return "verification_unavailable"
                
            stored_mac_b64 = stored_hash[3:]
            try:
                stored_mac = base64.b64decode(stored_mac_b64)
            except Exception:
                return "mismatch"
                
            computed_mac = hmac.new(key, canonical_string.encode('utf-8'), hashlib.sha256).digest()
            if hmac.compare_digest(computed_mac, stored_mac):
                record_verified = True
            else:
                return "mismatch"
                
        elif len(stored_hash) == 64 and all(c in "0123456789abcdefABCDEF" for c in stored_hash):
            computed_hash = hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()
            if hmac.compare_digest(computed_hash.encode('utf-8'), stored_hash.encode('utf-8')):
                record_verified = True
                is_legacy = True
            else:
                return "mismatch"
        else:
            return "verification_unavailable"
            
        # If record is valid, check the chain if db_session is provided
        if record_verified and db_session and getattr(record, 'previous_hash', None):
            from sqlalchemy import select, inspect
            
            mapper = inspect(record.__class__)
            table = mapper.local_table
            
            stmt = select(table.c.evidence_hash).where(
                table.c.session_id == record.session_id,
                table.c.id < record.id
            ).order_by(table.c.id.desc()).limit(1)
            
            actual_previous_hash = db_session.execute(stmt).scalar()
            
            if actual_previous_hash != record.previous_hash:
                return "chain_broken"
                
        return "verified_legacy" if is_legacy else "verified"
            
    except Exception as e:
        return "verification_unavailable"
