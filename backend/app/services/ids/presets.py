"""Pre-built multi-stage attack simulation presets (Priority 10).

Each preset is a narrative sequence of catalog attack ids ("stages"). The
frontend launches a preset by submitting each stage in sequence so the analyst
watches the attack unfold step-by-step, correlating detections across the
kill chain.
"""
from typing import Any, Dict, List

PRESETS: List[Dict[str, Any]] = [
    {
        "id": "apt_simulation",
        "name": "APT Simulation",
        "tagline": "Multi-stage: Recon → Exploit → Lateral Movement → Exfiltration",
        "narrative": "A patient intrusion begins with stealthy reconnaissance, escalates through an "
                     "application exploit, moves laterally via a reverse shell, and ends in covert exfiltration.",
        "stages": [
            {"attack_id": "os_fingerprinting", "beat": "Recon: fingerprinting the target stack"},
            {"attack_id": "service_enumeration", "beat": "Recon: enumerating exposed services"},
            {"attack_id": "sqli_union", "beat": "Exploit: SQL injection against the web tier"},
            {"attack_id": "reverse_shell", "beat": "Lateral: interactive shell back to attacker"},
            {"attack_id": "dns_tunneling", "beat": "Exfil: data smuggled over DNS"},
        ],
    },
    {
        "id": "ddos_attack",
        "name": "DDoS Attack",
        "tagline": "High-volume flood from multiple spoofed sources",
        "narrative": "A coordinated volumetric assault: reconnaissance is skipped and the target is "
                     "immediately buried under SYN and UDP floods plus reflected DNS amplification.",
        "stages": [
            {"attack_id": "ddos_syn_flood", "beat": "Volumetric SYN flood engages"},
            {"attack_id": "ddos_udp_flood", "beat": "Random UDP flood saturates bandwidth"},
            {"attack_id": "dns_amplification", "beat": "Reflected DNS amplification peaks"},
        ],
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat",
        "tagline": "Unusual data access outside working hours",
        "narrative": "A trusted account deviates from baseline: credential abuse opens the door, then "
                     "activity hides inside legitimate encrypted tunnels.",
        "stages": [
            {"attack_id": "password_spraying", "beat": "Spraying to find a weak account"},
            {"attack_id": "session_hijacking", "beat": "Hijacking a live privileged session"},
            {"attack_id": "encrypted_tunnel", "beat": "Staging data inside covert TLS"},
        ],
    },
    {
        "id": "ransomware_c2",
        "name": "Ransomware C2",
        "tagline": "Command-and-control beacon communication",
        "narrative": "Post-encryption, the implant phones home: periodic beacons coordinate "
                     "tasking while obfuscated payloads keep the signer blind.",
        "stages": [
            {"attack_id": "c2_beacon", "beat": "Jittered beacon check-in"},
            {"attack_id": "encoded_payload", "beat": "Encoded tasking response"},
            {"attack_id": "polymorphic_payload", "beat": "Polymorphic dropper rotates"},
        ],
    },
    {
        "id": "zero_day_exploit",
        "name": "Zero-Day Exploit",
        "tagline": "Novel pattern that only ML can catch (bypasses rules)",
        "narrative": "An unknown technique produces no matching signature; detection relies "
                     "entirely on anomaly scoring flagging statistical deviation.",
        "stages": [
            {"attack_id": "polymorphic_payload", "beat": "Novel obfuscated delivery (low signature coverage)"},
            {"attack_id": "encrypted_tunnel", "beat": "Covert high-entropy channel"},
        ],
    },
    {
        "id": "data_exfiltration",
        "name": "Data Exfiltration",
        "tagline": "Slow data leak via DNS tunneling",
        "narrative": "A low-and-slow leak: enumeration identifies a channel, then data drips "
                     "out via DNS tunneling and ICMP to evade thresholds.",
        "stages": [
            {"attack_id": "service_enumeration", "beat": "Identify outbound channel"},
            {"attack_id": "dns_tunneling", "beat": "Primary DNS exfil path"},
            {"attack_id": "icmp_tunneling", "beat": "Backup ICMP channel"},
            {"attack_id": "slow_rate_attack", "beat": "Low cadence to dodge rate rules"},
        ],
    },
    {
        "id": "supply_chain_attack",
        "name": "Supply Chain Attack",
        "tagline": "Compromised update mechanism",
        "narrative": "Trust is abused: DNS spoofing redirects an update check, delivering a "
                     "file-upload webshell that opens a reverse shell for persistence.",
        "stages": [
            {"attack_id": "dns_spoofing", "beat": "Redirect the update endpoint"},
            {"attack_id": "file_upload_exploit", "beat": "Drop webshell via update"},
            {"attack_id": "reverse_shell", "beat": "Attacker regains interactive access"},
        ],
    },
]


def list_presets() -> List[Dict[str, Any]]:
    return PRESETS


def get_preset(preset_id: str) -> Dict[str, Any]:
    for p in PRESETS:
        if p["id"] == preset_id:
            return p
    raise KeyError(f"Unknown preset id: {preset_id}")
