import pandas as pd
import numpy as np
import random
import re
import ipaddress
import datetime as dt

RANDOM_SEED = 42
TOTAL_LOGS = 1250
FLAGGED_COUNTS = {
    "hostname": 30,
    "domain": 80,
    "ipv4": 235,
    "url": 43,
    "hash": 62,
}

OLD_IOC_RATIO = 0.78  # 78% from old file
NEW_IOC_RATIO = 0.22  # 22% from new file
OLD_IOC_PATH = "ioc_finished.csv"
NEW_IOC_PATH = "otx_generated_iocs_20251223.csv"
OUT_CSV = "synthetic_network_logs_v2.csv"
OUT_JSONL = "synthetic_network_logs_v2.jsonl"

def _norm(s: str) -> str:
    return str(s).strip().lower()


def random_private_ip() -> str:
    blocks = [("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16)]
    base, prefix = random.choice(blocks)
    net = ipaddress.ip_network(f"{base}/{prefix}")
    host_int = random.randint(1, net.num_addresses - 2)
    return str(net.network_address + host_int)


def random_public_ip_avoid(avoid_set: set[str]) -> str:
    while True:
        ip = ".".join(str(random.randint(1, 223)) for _ in range(4))
        if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
            continue
        a, b, *_ = ip.split(".")
        if a == "172" and 16 <= int(b) <= 31:
            continue
        if ip in avoid_set:
            continue
        return ip


def severity_for(ioc_type: str, attack_type: str) -> str:
    s = str(attack_type).lower()
    if ioc_type == "hash":
        return "Critical"
    if any(k in s for k in ["ransom", "botnet", "c2"]):
        return "Critical"
    if any(k in s for k in ["phishing", "malware"]):
        return "High"
    if any(k in s for k in ["brute", "scan", "sweep"]):
        return "Medium"
    return "Low"


def pick_protocol_and_ports(ioc_type: str, attack_type: str) -> tuple[str, int, int]:
    s = str(attack_type).lower()
    if ioc_type in ("domain", "hostname"):
        proto = random.choice(["UDP", "TCP"])
        dport = 53 if proto == "UDP" else 443
    elif ioc_type == "url":
        proto = "TCP"
        dport = random.choice([80, 443])
    elif ioc_type == "hash":
        proto = "TCP"
        dport = random.choice([80, 443, 445])
    else:  # ipv4
        proto = "TCP"
        if "ssh" in s:
            dport = 22
        elif "rdp" in s:
            dport = 3389
        elif "smb" in s:
            dport = 445
        elif "http" in s:
            dport = 80
        else:
            dport = random.choice([22, 80, 443, 445, 3389])
    sport = random.randint(1024, 65535)
    return proto, sport, dport


def packet_type_for(proto: str, ioc_type: str) -> str:
    if ioc_type in ("domain", "hostname") and proto == "UDP":
        return random.choice(["DNS Query", "DNS Response"])
    if proto == "ICMP":
        return random.choice(["ICMP Echo Request", "ICMP Echo Reply"])
    return random.choice(["SYN", "ACK", "PSH", "FIN", "RST"])


BENIGN_DOMAINS = [
    "example.com", "example.org", "example.net",
    "safe-site.org", "corp.internal", "intranet.local",
]
BENIGN_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.5.0",
    "Wget/1.21.4",
    "python-requests/2.32.3",
]


def benign_payload(dport: int) -> str:
    if dport == 53:
        return f"DNS Query: {random.choice(BENIGN_DOMAINS)}"
    if dport in (80, 443):
        dom = random.choice(BENIGN_DOMAINS)
        path = random.choice(["/", "/login", "/api/v1/status", "/images/logo.png", "/dashboard"])
        scheme = "https" if dport == 443 else "http"
        ua = random.choice(BENIGN_UA)
        return f'HTTP GET {scheme}://{dom}{path} UA="{ua}"'
    return "No payload (encrypted or not captured)"


FIELDS = [
    "Timestamp", "Source IP Address", "Destination IP Address", "Source Port",
    "Destination Port", "Protocol", "Packet Length", "Packet Type", "Traffic Type",
    "Payload Data", "Alerts/Warnings", "Attack Type", "Attack Signature",
    "Action Taken", "Severity Level", "Device Information", "Log Source",
]


def base_log() -> dict:
    return {k: None for k in FIELDS}


def build_flagged_log(ioc_type: str, indicator: str, attack_type: str, ioc_ipv4_set: set[str]) -> dict:
    log = base_log()
    proto, sport, dport = pick_protocol_and_ports(ioc_type, attack_type)
    log["Protocol"] = proto
    log["Source Port"] = sport
    log["Destination Port"] = dport
    log["Packet Length"] = random.randint(60, 1500)
    log["Packet Type"] = packet_type_for(proto, ioc_type)
    log["Alerts/Warnings"] = f"IOC_MATCH ({ioc_type.upper()}): {indicator}"
    log["Attack Type"] = attack_type
    log["Attack Signature"] = f"{attack_type} | IOC:{ioc_type}:{indicator}"
    log["Severity Level"] = severity_for(ioc_type, attack_type)

    if ioc_type == "ipv4":
        log["Traffic Type"] = "Inbound"
        log["Source IP Address"] = indicator
        log["Destination IP Address"] = random_private_ip()
        log["Action Taken"] = random.choice(["Blocked", "Reset Connection", "Allowed (monitored)"])
        log["Device Information"] = random.choice(["FW-01 (FortiGate 100F)", "IDS-01 (Suricata)"])
        log["Log Source"] = random.choice(["firewall", "ids"])
        log["Payload Data"] = f"{log['Packet Type']} to port {dport} from {indicator}"
    elif ioc_type in ("domain", "hostname"):
        log["Traffic Type"] = "Outbound"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_public_ip_avoid(ioc_ipv4_set)
        log["Action Taken"] = random.choice(["Blocked", "Allowed (logged)", "Sinkholed"])
        log["Device Information"] = random.choice(["DNS-01 (BIND9)", "PROXY-01 (Squid)", "FW-01 (FortiGate 100F)"])
        log["Log Source"] = random.choice(["dns", "proxy", "firewall"])
        qtype = "DNS Query" if dport == 53 else "TLS SNI"
        log["Payload Data"] = f"{qtype}: {indicator}"
    elif ioc_type == "url":
        log["Traffic Type"] = "Outbound"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_public_ip_avoid(ioc_ipv4_set)
        log["Action Taken"] = random.choice(["Blocked", "Allowed (logged)"])
        log["Device Information"] = random.choice(["PROXY-01 (Squid)", "FW-01 (FortiGate 100F)", "IDS-01 (Suricata)"])
        log["Log Source"] = random.choice(["proxy", "firewall", "ids"])
        log["Payload Data"] = f"HTTP Request: GET {indicator}"
    elif ioc_type == "hash":
        log["Traffic Type"] = "Host"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_private_ip()
        log["Action Taken"] = random.choice(["Quarantined", "Blocked", "Isolated Host"])
        log["Device Information"] = random.choice(
            ["EDR-01 (Windows Defender for Endpoint)", "EDR-02 (CrowdStrike Falcon)"])
        log["Log Source"] = "endpoint"
        log["Payload Data"] = f"File execution blocked. MD5={indicator}"
    return log


def build_benign_log(ioc_ipv4_set: set[str]) -> dict:
    log = base_log()
    pattern = random.choice(["web_out", "dns_out", "inbound_ok", "lateral", "icmp"])
    if pattern == "web_out":
        log["Traffic Type"] = "Outbound"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_public_ip_avoid(ioc_ipv4_set)
        log["Protocol"] = "TCP"
        log["Source Port"] = random.randint(1024, 65535)
        log["Destination Port"] = random.choice([80, 443])
        log["Packet Type"] = packet_type_for("TCP", "url")
        log["Packet Length"] = random.randint(200, 1500)
        log["Payload Data"] = benign_payload(log["Destination Port"])
        log["Log Source"] = random.choice(["proxy", "firewall"])
        log["Device Information"] = random.choice(["PROXY-01 (Squid)", "FW-01 (FortiGate 100F)"])
    elif pattern == "dns_out":
        log["Traffic Type"] = "Outbound"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_private_ip()
        log["Protocol"] = "UDP"
        log["Source Port"] = random.randint(1024, 65535)
        log["Destination Port"] = 53
        log["Packet Type"] = packet_type_for("UDP", "domain")
        log["Packet Length"] = random.randint(80, 400)
        log["Payload Data"] = benign_payload(53)
        log["Log Source"] = "dns"
        log["Device Information"] = "DNS-01 (BIND9)"
    elif pattern == "inbound_ok":
        log["Traffic Type"] = "Inbound"
        log["Source IP Address"] = random_public_ip_avoid(ioc_ipv4_set)
        log["Destination IP Address"] = random_private_ip()
        log["Protocol"] = "TCP"
        log["Source Port"] = random.randint(1024, 65535)
        log["Destination Port"] = random.choice([443, 80, 22])
        log["Packet Type"] = packet_type_for("TCP", "ipv4")
        log["Packet Length"] = random.randint(60, 1200)
        log["Payload Data"] = "Normal connection establishment"
        log["Log Source"] = "firewall"
        log["Device Information"] = "FW-01 (FortiGate 100F)"
    elif pattern == "lateral":
        log["Traffic Type"] = "Lateral"
        log["Source IP Address"] = random_private_ip()
        log["Destination IP Address"] = random_private_ip()
        log["Protocol"] = "TCP"
        log["Source Port"] = random.randint(1024, 65535)
        log["Destination Port"] = random.choice([445, 3389, 389])
        log["Packet Type"] = packet_type_for("TCP", "ipv4")
        log["Packet Length"] = random.randint(100, 1500)
        log["Payload Data"] = "Internal service access"
        log["Log Source"] = random.choice(["firewall", "ids"])
        log["Device Information"] = random.choice(["FW-01 (FortiGate 100F)", "IDS-01 (Suricata)"])
    else:  # icmp
        log["Traffic Type"] = "Inbound"
        log["Source IP Address"] = random_public_ip_avoid(ioc_ipv4_set)
        log["Destination IP Address"] = random_private_ip()
        log["Protocol"] = "ICMP"
        log["Source Port"] = 0
        log["Destination Port"] = 0
        log["Packet Type"] = packet_type_for("ICMP", "ipv4")
        log["Packet Length"] = random.randint(60, 200)
        log["Payload Data"] = "ICMP ping"
        log["Log Source"] = "firewall"
        log["Device Information"] = "FW-01 (FortiGate 100F)"
    log["Alerts/Warnings"] = "None"
    log["Attack Type"] = "None"
    log["Attack Signature"] = "None"
    log["Action Taken"] = "Allowed"
    log["Severity Level"] = "Info"
    return log


def load_iocs(csv_path: str) -> pd.DataFrame:
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Error: Could not find {csv_path}")
        return pd.DataFrame()

    required_cols = {"Indicator type", "Indicator", "Type"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"File {csv_path} is missing columns: {missing}.")

    type_map = {
        "ipv4": "ipv4",
        "domain": "domain",
        "hostname": "hostname",
        "url": "url",
        "filehash-md5": "hash",
        "md5": "hash",
        "hash": "hash",
    }
    df["ioc_type"] = df["Indicator type"].map(_norm).map(lambda x: type_map.get(x, x))
    df["indicator"] = df["Indicator"].astype(str).str.strip()
    df["attack_type"] = df["Type"].astype(str).str.strip()

    def _mode(series: pd.Series) -> str:
        return series.value_counts().idxmax()

    uniq = (
        df.groupby(["ioc_type", "indicator"], as_index=False)
        .agg({"attack_type": _mode})
    )
    return uniq


def main() -> None:
    random.seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    print("Loading IOCs...")
    df_old = load_iocs(OLD_IOC_PATH)
    df_new = load_iocs(NEW_IOC_PATH)

    if df_old.empty or df_new.empty:
        print("CRITICAL ERROR: One of the IOC files is empty or missing.")
        return

    all_malicious_ips = set(df_old[df_old["ioc_type"] == "ipv4"]["indicator"]) | \
                        set(df_new[df_new["ioc_type"] == "ipv4"]["indicator"])

    logs: list[dict] = []

    print("\nGenerating malicious logs (78% Old / 22% New)...")
    for ioc_type, count in FLAGGED_COUNTS.items():
        count_old = int(count * OLD_IOC_RATIO)
        count_new = count - count_old

        print(f" - {ioc_type.upper()}: {count} total ({count_old} old, {count_new} new)")

        pool_old = df_old[df_old["ioc_type"] == ioc_type]
        if not pool_old.empty:
            sample_old = pool_old.sample(n=count_old, replace=(len(pool_old) < count_old), random_state=RANDOM_SEED)
            for _, row in sample_old.iterrows():
                logs.append(build_flagged_log(ioc_type, row["indicator"], row["attack_type"], all_malicious_ips))
        else:
            print(f"   [!] Warning: No old IOCs for {ioc_type}")

        pool_new = df_new[df_new["ioc_type"] == ioc_type]
        if not pool_new.empty:
            sample_new = pool_new.sample(n=count_new, replace=(len(pool_new) < count_new), random_state=RANDOM_SEED + 1)
            for _, row in sample_new.iterrows():
                logs.append(build_flagged_log(ioc_type, row["indicator"], row["attack_type"], all_malicious_ips))
        else:
            print(f"   [!] Warning: No new IOCs for {ioc_type}")

    total_flagged = len(logs)
    print(f"\nTotal Flagged Logs Generated: {total_flagged}")

    total_benign = TOTAL_LOGS - total_flagged
    print(f"Generating {total_benign} benign logs...")

    for _ in range(total_benign):
        logs.append(build_benign_log(all_malicious_ips))

    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=21)
    span_seconds = int((now - start).total_seconds())

    for log in logs:
        ts = start + dt.timedelta(seconds=random.randint(0, span_seconds))
        log["Timestamp"] = ts.isoformat().replace("+00:00", "Z")

    random.shuffle(logs)
    df_logs = pd.DataFrame(logs)[FIELDS]

    df_logs.to_csv(OUT_CSV, index=False)
    df_logs.to_json(OUT_JSONL, orient="records", lines=True)

    print(f"\nSUCCESS! Saved {len(df_logs)} logs to:")
    print(f"- {OUT_CSV}")
    print(f"- {OUT_JSONL}")


if __name__ == "__main__":
    main()