"""Attack-type catalog for the expanded IDS payload-submission module.

Each attack type carries:
  * descriptive metadata (name, category, description, severity)
  * MITRE ATT&CK technique/tactic mappings
  * Lockheed Martin Cyber Kill Chain stage
  * threat-intelligence references (CVEs, actors, NIST / OWASP, mitigations)
  * a synthetic-telemetry *generation profile* consumed by ``packet_generator``

Categories and the ordered list of attack ids per category are exported so the
frontend can render a grouped payload selector without hardcoding anything.
"""
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Category taxonomy (ordered for UI display)
# ---------------------------------------------------------------------------
CATEGORIES: List[Dict[str, str]] = [
    {"id": "reconnaissance", "name": "Reconnaissance", "blurb": "Discovery & enumeration prior to exploitation"},
    {"id": "authentication", "name": "Authentication Attacks", "blurb": "Credential abuse & session compromise"},
    {"id": "injection", "name": "Injection Attacks", "blurb": "Application-layer payload injection"},
    {"id": "network", "name": "Network Attacks", "blurb": "Flooding, spoofing & interception"},
    {"id": "malware", "name": "Malware / Payload Delivery", "blurb": "Implants, shells & C2"},
    {"id": "evasion", "name": "Evasion Techniques", "blurb": "Detection-avoidance behaviour"},
    {"id": "baseline", "name": "Normal Traffic", "blurb": "Benign ground-truth for clean verdicts"},
]


def _a(
    id_: str,
    name: str,
    category: str,
    severity: str,
    description: str,
    mitre: List[Dict[str, str]],
    kill_chain: str,
    profile: Dict[str, Any],
    threat: Dict[str, Any] = None,
) -> Dict[str, Any]:
    return {
        "id": id_,
        "name": name,
        "category": category,
        "severity": severity,
        "description": description,
        "mitre": mitre,
        "kill_chain_stage": kill_chain,
        "profile": profile,
        "threat_intel": threat or {},
    }


# Generation-profile keys used by packet_generator:
#   protocol      TCP | UDP | HTTP | DNS | ICMP | ARP | TLS
#   dst_ports     list of destination ports (rotated)
#   src_port_mode ephemeral | fixed | random
#   flags         TCP flag string (SYN, FIN, RST, PSH-ACK, SYN-ACK, NONE, ...)
#   ttl           base TTL value, jittered +/-
#   size          (min,max) packet byte size
#   rate          baseline packets/second (drives inter-arrival time)
#   payload_style key understood by packet_generator content builder
CATALOG: Dict[str, Dict[str, Any]] = {
    a["id"]: a
    for a in [
        # ===================== RECONNAISSANCE =====================
        _a("port_scan_syn", "Port Scan (SYN / Stealth)", "reconnaissance", "medium",
           "Half-open TCP SYN probes across many ports; no completing handshake.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443],
            "src_port_mode": "ephemeral", "flags": "SYN", "ttl": 64, "size": (40, 60), "rate": 120,
            "payload_style": "empty"},
           {"actors": ["apt_scan_generic"], "nist": ["SI.RA-1"], "owasp": ["A01 Broken Access Control"],
            "mitigations": ["Rate-limit inbound SYN", "Deploy port-scan detection signatures", "Close unused services"]}),
        _a("port_scan_fin", "Port Scan (FIN)", "reconnaissance", "low",
           "FIN probes used to bypass stateful filters and map closed/open ports.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [22, 80, 443, 445, 3389, 8080], "src_port_mode": "ephemeral",
            "flags": "FIN", "ttl": 64, "size": (40, 52), "rate": 90, "payload_style": "empty"}),
        _a("port_scan_xmas", "Port Scan (XMAS)", "reconnaissance", "low",
           "FIN+PSH+URG flags set (Christmas-tree packet) to elicit RST responses.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [21, 22, 23, 80, 443, 3389], "src_port_mode": "ephemeral",
            "flags": "FIN,PSH,URG", "ttl": 64, "size": (40, 52), "rate": 80, "payload_style": "empty"}),
        _a("port_scan_null", "Port Scan (NULL)", "reconnaissance", "low",
           "TCP packets with no flags set, probing RFC 793 stack behaviour.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [22, 80, 443, 445], "src_port_mode": "ephemeral",
            "flags": "NONE", "ttl": 64, "size": (40, 52), "rate": 80, "payload_style": "empty"}),
        _a("network_mapping", "Network Mapping / Host Discovery", "reconnaissance", "medium",
           "ICMP echo + broadcast sweeps to enumerate live hosts on a subnet.",
           [{"technique_id": "T1018", "technique_name": "Remote System Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "ICMP", "dst_ports": [0], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (28, 64), "rate": 60, "payload_style": "icmp_echo"}),
        _a("os_fingerprinting", "OS Fingerprinting", "reconnaissance", "low",
           " crafted TCP window/TTL/option probes to infer remote operating system.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [22, 80, 443], "src_port_mode": "ephemeral", "flags": "SYN",
            "ttl": 128, "size": (44, 68), "rate": 50, "payload_style": "syn_options"}),
        _a("service_enumeration", "Service Enumeration", "reconnaissance", "medium",
           "Banner-grabbing and RPC/SMB enumeration against discovered services.",
           [{"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"}],
           "reconnaissance",
           {"protocol": "TCP", "dst_ports": [21, 22, 25, 80, 135, 139, 443, 445, 3389], "src_port_mode": "ephemeral",
            "flags": "PSH-ACK", "ttl": 64, "size": (60, 220), "rate": 40, "payload_style": "banner"}),

        # ===================== AUTHENTICATION =====================
        _a("brute_force", "Brute Force Login", "authentication", "high",
           "High-velocity repeated credential attempts against a single account.",
           [{"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"}],
           "installation",
           {"protocol": "HTTP", "dst_ports": [22, 443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (200, 420), "rate": 8, "payload_style": "auth_attempt"},
           {"cves": ["CVE-2021-44228 (context)"], "nist": ["IA-5 Authentication"], "owasp": ["A07 Identification & Authentication Failures"],
            "mitigations": ["Account lockout after 5 failures", "Enforce MFA", "Progressive tarpitting", "IP reputation filtering"]}),
        _a("credential_stuffing", "Credential Stuffing", "authentication", "high",
           "Automated logins using leaked user/pass pairs across many accounts.",
           [{"technique_id": "T1110.004", "technique_name": "Credential Stuffing", "tactic": "Credential Access"}],
           "installation",
           {"protocol": "HTTP", "dst_ports": [443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (240, 520), "rate": 12, "payload_style": "auth_spray"},
           {"owasp": ["A07 Identification & Authentication Failures"], "mitigations": ["CAPTCHA / JS challenges", "Breach-list monitoring", "Device fingerprinting"]}),
        _a("password_spraying", "Password Spraying", "authentication", "medium",
           "One common password tried across many accounts to stay under lockout thresholds.",
           [{"technique_id": "T1110.003", "technique_name": "Password Spraying", "tactic": "Credential Access"}],
           "installation",
           {"protocol": "HTTP", "dst_ports": [443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (220, 460), "rate": 3, "payload_style": "auth_spray"}),
        _a("dictionary_attack", "Dictionary Attack", "authentication", "medium",
           "Sequential guesses drawn from a curated wordlist against an auth endpoint.",
           [{"technique_id": "T1110.001", "technique_name": "Password Guessing", "tactic": "Credential Access"}],
           "installation",
           {"protocol": "HTTP", "dst_ports": [22, 443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (180, 360), "rate": 6, "payload_style": "auth_dict"}),
        _a("session_hijacking", "Session Hijacking", "authentication", "high",
           "Reuse/theft of a valid session token after interception or prediction.",
           [{"technique_id": "T1563.001", "technique_name": "Session Hijacking (Remote)", "tactic": "Lateral Movement"}],
           "actions",
           {"protocol": "HTTP", "dst_ports": [443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (260, 480), "rate": 4, "payload_style": "session_token"},
           {"owasp": ["A07"], "mitigations": ["Bind sessions to IP+UA", "Rotate tokens", "Short idle timeouts", "HSTS"]}),
        _a("token_replay", "Token Replay Attack", "authentication", "medium",
           "Captured authentication token re-submitted to impersonate a principal.",
           [{"technique_id": "T1550.004", "technique_name": "Replay Attacks", "tactic": "Defense Evasion"}],
           "actions",
           {"protocol": "HTTP", "dst_ports": [443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (300, 640), "rate": 5, "payload_style": "bearer_replay"},
           {"mitigations": ["Nonce/timestamp binding", "Server-side replay cache", "One-time tokens"]}),

        # ===================== INJECTION =====================
        _a("sqli_union", "SQL Injection (UNION-based)", "injection", "high",
           "UNION SELECT payloads exfiltrating columns from database responses.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (280, 900), "rate": 6, "payload_style": "sqli_union"},
           {"owasp": ["A03 Injection"], "cves": ["CVE-2017-5638 (context)"], "mitigations": ["Parameterised queries", "Least-privilege DB accounts", "WAF virtual patching"]}),
        _a("sqli_blind", "SQL Injection (Boolean-blind)", "injection", "high",
           "True/false inference queries probing data one bit at a time.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (260, 720), "rate": 10, "payload_style": "sqli_blind"}),
        _a("sqli_time", "SQL Injection (Time-based)", "injection", "high",
           "SLEEP/BENCHMARK injections causing measurable response-time side channels.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (260, 700), "rate": 4, "payload_style": "sqli_time"}),
        _a("command_injection", "OS Command Injection", "injection", "critical",
           "Shell metacharacter chains executing arbitrary OS commands.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "exploitation",
           {"protocol": "HTTP", "dst_ports": [80, 443, 8080], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (260, 640), "rate": 5, "payload_style": "cmd_inject"},
           {"owasp": ["A03 Injection"], "mitigations": ["Avoid shell invocation", "Strict input allow-listing", "Sandbox egress"]}),
        _a("ldap_injection", "LDAP Injection", "injection", "high",
           "Manipulated LDAP filters dereferencing directory objects.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "delivery",
           {"protocol": "TCP", "dst_ports": [389, 636], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (220, 520), "rate": 5, "payload_style": "ldap_inject"}),
        _a("xss_reflected", "XSS (Reflected)", "injection", "medium",
           "Script payloads echoed from request parameters into the response body.",
           [{"technique_id": "T1059.007", "technique_name": "JavaScript", "tactic": "Execution"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (240, 700), "rate": 6, "payload_style": "xss_reflect"},
           {"owasp": ["A03 Injection"], "mitigations": ["Contextual output encoding", "CSP nonce", "Input sanitisation"]}),
        _a("xss_stored", "XSS (Stored)", "injection", "high",
           "Persisted script payloads served to subsequent victims from the datastore.",
           [{"technique_id": "T1059.007", "technique_name": "JavaScript", "tactic": "Execution"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (320, 960), "rate": 4, "payload_style": "xss_stored"}),
        _a("xss_dom", "XSS (DOM-based)", "injection", "medium",
           "Client-side sinks (innerHTML/location) executing injected DOM script.",
           [{"technique_id": "T1059.007", "technique_name": "JavaScript", "tactic": "Execution"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (240, 640), "rate": 5, "payload_style": "xss_dom"}),
        _a("xxe_injection", "XML / XXE Injection", "injection", "high",
           "External-entity XML documents disclosing local files / SSRF.",
           [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443, 8443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (320, 880), "rate": 4, "payload_style": "xxe"},
           {"owasp": ["A05 Security Misconfiguration"], "mitigations": ["Disable external entities/DTD", "Use JSON where possible"]}),

        # ===================== NETWORK =====================
        _a("ddos_syn_flood", "DDoS (SYN Flood)", "network", "critical",
           "Overwhelming half-open SYN volume exhausting connection tables.",
           [{"technique_id": "T1498.001", "technique_name": "SYN Flooding", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "TCP", "dst_ports": [80, 443], "src_port_mode": "random", "flags": "SYN",
            "ttl": 64, "size": (40, 60), "rate": 500, "payload_style": "empty", "spoof_src": True},
           {"mitigations": ["SYN cookies", "Connection rate limiting", "Anycast scrubbing", "Upstream ACL"]}),
        _a("ddos_udp_flood", "DDoS (UDP Flood)", "network", "critical",
           "High-volume random UDP datagrams saturating bandwidth.",
           [{"technique_id": "T1498", "technique_name": "Network Denial of Service", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "UDP", "dst_ports": [53, 123, 161, 1900, 3478, 5060], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (60, 1400), "rate": 600, "payload_style": "udp_noise", "spoof_src": True}),
        _a("ddos_http_flood", "DDoS (HTTP Flood / L7)", "network", "high",
           "Seemingly-valid HTTP requests exhausting application resources.",
           [{"technique_id": "T1498.002", "technique_name": "OSI Application Flood", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (300, 800), "rate": 200, "payload_style": "http_get"}),
        _a("slowloris", "Slowloris (Slow Connection)", "network", "high",
           "Many sockets held open with continual partial HTTP header updates.",
           [{"technique_id": "T1499.001", "technique_name": "Internal Denial of Service", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (120, 220), "rate": 2, "payload_style": "slowloris"}),
        _a("dns_amplification", "DNS Amplification", "network", "critical",
           "Spoofed small TXT queries reflected as large answers to a victim.",
           [{"technique_id": "T1498.001", "technique_name": "Reflection Amplification", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "UDP", "dst_ports": [53], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (512, 4096), "rate": 300, "payload_style": "dns_amplify", "spoof_src": True}),
        _a("arp_spoofing", "ARP Spoofing / Poisoning", "network", "high",
           "Gratuitous ARP replies remapping the gateway MAC for MITM.",
           [{"technique_id": "T1557.002", "technique_name": "ARP Cache Poisoning", "tactic": "Credential Access"}],
           "exploitation",
           {"protocol": "ARP", "dst_ports": [0], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (42, 42), "rate": 20, "payload_style": "arp_reply"}),
        _a("dns_spoofing", "DNS Spoofing / Cache Poisoning", "network", "high",
           "Forged DNS responses poisoning resolver caches.",
           [{"technique_id": "T1584.001", "technique_name": "DNS Server", "tactic": "Resource Development"}],
           "exploitation",
           {"protocol": "UDP", "dst_ports": [53], "src_port_mode": "fixed", "flags": "NONE",
            "ttl": 64, "size": (80, 240), "rate": 15, "payload_style": "dns_response_spoof"}),
        _a("mitm", "Man-in-the-Middle (MITM)", "network", "critical",
           "Interception & relaying of a TLS/HTTP session between endpoints.",
           [{"technique_id": "T1557", "technique_name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
           "exploitation",
           {"protocol": "TLS", "dst_ports": [443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (200, 700), "rate": 30, "payload_style": "mitm_relay"},
           {"mitigations": ["Certificate pinning", "HSTS preload", "Detect ARP/DNS anomalies"]}),
        _a("ip_spoofing", "IP Spoofing", "network", "high",
           "Inbound packets with forged source addresses impersonating trusted hosts.",
           [{"technique_id": "T1589", "technique_name": "Gather Victim Identity Info", "tactic": "Reconnaissance"}],
           "delivery",
           {"protocol": "TCP", "dst_ports": [22, 445, 3389], "src_port_mode": "random", "flags": "SYN",
            "ttl": 64, "size": (40, 60), "rate": 80, "payload_style": "empty", "spoof_src": True}),

        # ===================== MALWARE / PAYLOAD DELIVERY =====================
        _a("reverse_shell", "Reverse Shell Payload", "malware", "critical",
           "Outbound interactive shell connecting back to an attacker listener.",
           [{"technique_id": "T1059", "technique_name": "Command & Scripting Interpreter", "tactic": "Execution"}],
           "exploitation",
           {"protocol": "TCP", "dst_ports": [4444, 9001, 1337], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (120, 600), "rate": 10, "payload_style": "reverse_shell"},
           {"mitigations": ["Egress filtering", "Appallow outbound", "Detect /dev/tcp & nc patterns"]}),
        _a("encoded_payload", "Encoded / Obfuscated Payload", "malware", "high",
           "Base64/hex/rot payloads designed to slip past static signature match.",
           [{"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": "Defense Evasion"}],
           "delivery",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (300, 900), "rate": 6, "payload_style": "encoded"}),
        _a("file_upload_exploit", "File Upload Exploit (Webshell)", "malware", "critical",
           "Malicious file / webshell uploaded and then invoked over HTTP.",
           [{"technique_id": "T1100", "technique_name": "Web Shell", "tactic": "Persistence"}],
           "exploitation",
           {"protocol": "HTTP", "dst_ports": [80, 443, 8080], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (600, 2000), "rate": 4, "payload_style": "multipart_upload"},
           {"owasp": ["A03"], "mitigations": ["Validate file type/magic bytes", "Store outside webroot", "Scanning AV on upload"]}),
        _a("polymorphic_payload", "Polymorphic Payload", "malware", "high",
           "Byte-shifting implant whose signature mutates every transmission.",
           [{"technique_id": "T1027.005", "technique_name": "Indicator Removal / Polymorphism", "tactic": "Defense Evasion"}],
           "delivery",
           {"protocol": "TCP", "dst_ports": [443, 4444, 8443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (300, 1200), "rate": 8, "payload_style": "polymorphic"}),
        _a("c2_beacon", "C2 (Command & Control) Beacon", "malware", "critical",
           "Periodic jittered check-ins from an implant to a C2 server.",
           [{"technique_id": "T1071.001", "technique_name": "Web Protocols (C2)", "tactic": "Command and Control"}],
           "command_and_control",
           {"protocol": "HTTP", "dst_ports": [443, 8080], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (200, 500), "rate": 1, "payload_style": "c2_beacon", "beacon_interval_s": 30},
           {"mitigations": ["DNS/HTTP egress monitoring", "Jitter-beacon detection", "Threat-intel blocklists"]}),

        # ===================== EVASION =====================
        _a("fragmented_packets", "Fragmented Packets", "evasion", "medium",
           "IP fragmentation splitting headers to evade signature reassembly.",
           [{"technique_id": "T1027.003", "technique_name": "Steal or Session Hijacking / Frag", "tactic": "Defense Evasion"}],
           "delivery",
           {"protocol": "TCP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (40, 300), "rate": 40, "payload_style": "ip_fragment"}),
        _a("encrypted_tunnel", "Encrypted Tunnel (Covert Channel)", "evasion", "high",
           "Confidential byte-streams hidden inside legitimate TLS sessions.",
           [{"technique_id": "T1573", "technique_name": "Encrypted Channel", "tactic": "Command and Control"}],
           "command_and_control",
           {"protocol": "TLS", "dst_ports": [443, 8443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (200, 1400), "rate": 12, "payload_style": "tls_high_entropy"}),
        _a("dns_tunneling", "DNS Tunneling", "evasion", "high",
           "Data smuggled in long/recursive TXT/NULL DNS query labels.",
           [{"technique_id": "T1071.004", "technique_name": "DNS Tunneling", "tactic": "Command and Control"}],
           "exfiltration",
           {"protocol": "UDP", "dst_ports": [53], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (80, 512), "rate": 25, "payload_style": "dns_tunnel"},
           {"mitigations": ["Rate-limit per-client DNS", "Block TXT/NULL to external", "Inspect label entropy"]}),
        _a("icmp_tunneling", "ICMP Tunneling", "evasion", "medium",
           "Payload bytes embedded in ICMP echo data for covert C2/exfil.",
           [{"technique_id": "T1095", "technique_name": "Non-Application Layer Protocol", "tactic": "Command and Control"}],
           "command_and_control",
           {"protocol": "ICMP", "dst_ports": [0], "src_port_mode": "random", "flags": "NONE",
            "ttl": 64, "size": (56, 1000), "rate": 15, "payload_style": "icmp_data"}),
        _a("slow_rate_attack", "Slow-Rate Attack", "evasion", "medium",
           "Sub-threshold request cadence designed to avoid rate-based detection.",
           [{"technique_id": "T1499", "technique_name": "Endpoint Denial of Service", "tactic": "Impact"}],
           "exploitation",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "fixed", "flags": "PSH-ACK",
            "ttl": 64, "size": (200, 480), "rate": 1, "payload_style": "http_get"}),

        # ===================== BASELINE =====================
        _a("normal_traffic", "Normal Baseline Traffic", "baseline", "info",
           "Benign web/DNS traffic used to validate clean-verdict behaviour.",
           [{"technique_id": "-", "technique_name": "No MITRE mapping (benign)", "tactic": "-"}],
           "reconnaissance",
           {"protocol": "HTTP", "dst_ports": [80, 443], "src_port_mode": "ephemeral", "flags": "PSH-ACK",
            "ttl": 64, "size": (120, 640), "rate": 3, "payload_style": "benign_http"},
           {"mitigations": ["No action required - baseline reference traffic"]}),
    ]
}


def list_categories() -> List[Dict[str, Any]]:
    """Return categories with their ordered list of attack summaries."""
    out = []
    for cat in CATEGORIES:
        attacks = [
            {
                "id": a["id"],
                "name": a["name"],
                "severity": a["severity"],
                "description": a["description"],
                "kill_chain_stage": a["kill_chain_stage"],
                "mitre": a["mitre"],
            }
            for a in CATALOG.values()
            if a["category"] == cat["id"]
        ]
        out.append({**cat, "attacks": attacks})
    return out


def get_attack(attack_id: str) -> Dict[str, Any]:
    attack = CATALOG.get(attack_id)
    if not attack:
        raise KeyError(f"Unknown attack id: {attack_id}")
    return attack
