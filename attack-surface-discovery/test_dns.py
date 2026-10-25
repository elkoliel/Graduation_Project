
import subprocess
import json
import socket
from pathlib import Path
from datetime import datetime, timezone

SUBFINDER = (
    r"C:\Users\Noor\Downloads\subfinder_2.17.0_windows_amd64"
    r"\subfinder.exe"
)

DOMAIN = "koorator.online"
OUTPUT_FILE = Path("discovery_results.json")


def discover_subdomains(domain):
    result = subprocess.run(
        [SUBFINDER, "-d", domain, "-silent"],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )

    return sorted({
        line.strip().lower().rstrip(".")
        for line in result.stdout.splitlines()
        if line.strip()
    })


def resolve_ips(hostname):
    try:
        records = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
        return sorted({record[4][0] for record in records})
    except OSError:
        return []


def main():
    print(f"Discovering subdomains for {DOMAIN}...")

    try:
        subdomains = discover_subdomains(DOMAIN)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"Discovery failed: {error}")
        return

    assets = []

    for index, hostname in enumerate(subdomains, start=1):
        ips = resolve_ips(hostname)

        assets.append({
            "domain": hostname,
            "ip_addresses": ips,
            "dns_resolved": bool(ips),
        })

        if index % 25 == 0 or index == len(subdomains):
            print(
                f"Processed {index}/{len(subdomains)} subdomains"
            )

    if len(subdomains) != len(assets):
        print("Validation failed: counts do not match.")
        return

    output = {
    "schema_version": "1.0",
    "target_domain": DOMAIN,
    "discovered_at": datetime.now(timezone.utc).isoformat(),
    "total_subdomains": len(subdomains),
    "resolved_count": sum(
        asset["dns_resolved"] for asset in assets
    ),
    "assets": assets,
}

    OUTPUT_FILE.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )

    print("Validation passed: subdomains and assets counts match.")
    print(f"Discovered: {len(subdomains)}")
    print(f"DNS resolved: {output['resolved_count']}")
    print(f"Saved JSON to: {OUTPUT_FILE.resolve()}")


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired:
        print("Discovery timed out after 180 seconds.")
