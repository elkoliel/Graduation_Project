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
OUTPUT_FILE = "discovery_results.json"


def discover_subdomains(domain):
    result = subprocess.run(
        [SUBFINDER, "-d", domain, "-silent"],
        capture_output=True,
        text=True,
        timeout=180
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Subfinder failed")

    return sorted({
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip()
    })


def resolve_ips(hostname):
    try:
        records = socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
        return sorted({record[4][0] for record in records})
    except (socket.gaierror, OSError):
        return []


def main():
    print(f"Discovering subdomains for {DOMAIN}...")

    try:
        subdomains = discover_subdomains(DOMAIN)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Discovery failed: {error}")
        return

    assets = []

    for index, hostname in enumerate(subdomains, start=1):
        ips = resolve_ips(hostname)

        assets.append({
            "domain": hostname,
            "ip_addresses": ips,
            "dns_resolved": bool(ips)
        })

        if index % 25 == 0 or index == len(subdomains):
            print(f"Processed {index}/{len(subdomains)} subdomains")

    # Validate the collected data after the loop finishes.
    if len(subdomains) != len(assets):
        print(
            f"Warning: {len(subdomains)} subdomains "
            f"but {len(assets)} assets"
        )
        return

    print("Validation passed: subdomains and assets counts match.")

    output = {
        "target_domain": DOMAIN,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "total_subdomains": len(subdomains),
        "resolved_count": sum(
            asset["dns_resolved"] for asset in assets
        ),
        "assets": assets
    }

def test_dns_sample(domain, sample_size=10):
    print(f"\nTesting DNS for {domain}...")
    print(socket.getaddrinfo(
        domain, 443, type=socket.SOCK_STREAM
    ))

    print(f"\nTesting first {sample_size} discovered names:")
    try:
        with open(OUTPUT_FILE, encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        print(f"Could not read results: {error}")
        return

    for asset in data["assets"][:sample_size]:
        hostname = asset["domain"]
        try:
            ips = sorted({
                item[4][0]
                for item in socket.getaddrinfo(
                    hostname, None, type=socket.SOCK_STREAM
                )
            })
            print(f"{hostname}: {ips}")
        except OSError as error:
            print(f"{hostname}: DNS lookup failed ({error})")



    Path(OUTPUT_FILE).write_text(
        json.dumps(output, indent=2),
        encoding="utf-8"
    )

    print(f"\nDiscovered: {len(subdomains)}")
    print(f"DNS resolved: {output['resolved_count']}")
    print(f"Saved JSON to: {Path(OUTPUT_FILE).resolve()}")


if __name__ == "__main__":
    main()
