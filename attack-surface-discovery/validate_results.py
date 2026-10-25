
import json
from pathlib import Path

RESULTS_FILE = Path("discovery_results.json")


def main():
    if not RESULTS_FILE.exists():
        print("FAIL: discovery_results.json was not found.")
        return

    try:
        data = json.loads(
            RESULTS_FILE.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        print(f"FAIL: Cannot read JSON: {error}")
        return

    required_top = {
        "schema_version",
        "target_domain",
        "discovered_at",
        "total_subdomains",
        "resolved_count",
        "assets",
    }

    missing = required_top - data.keys()
    if missing:
        print(f"FAIL: Missing fields: {sorted(missing)}")
        return

    assets = data["assets"]
    if not isinstance(assets, list):
        print("FAIL: assets must be a list.")
        return

    required_asset = {
        "domain",
        "ip_addresses",
        "dns_resolved",
    }

    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            print(f"FAIL: Asset {index} is not an object.")
            return

        missing = required_asset - asset.keys()
        if missing:
            print(
                f"FAIL: Asset {index} missing fields: "
                f"{sorted(missing)}"
            )
            return

        if not isinstance(asset["ip_addresses"], list):
            print(f"FAIL: Asset {index} has invalid IP list.")
            return

        expected = bool(asset["ip_addresses"])
        if asset["dns_resolved"] != expected:
            print(f"FAIL: Asset {index} has inconsistent DNS status.")
            return

    resolved = sum(
        bool(asset["dns_resolved"]) for asset in assets
    )

    if data["total_subdomains"] != len(assets):
        print("FAIL: total_subdomains does not match assets.")
        return

    if data["resolved_count"] != resolved:
        print("FAIL: resolved_count does not match assets.")
        return

    print("PASS: Discovery JSON is structurally valid.")
    print(f"Schema: {data['schema_version']}")
    print(f"Target: {data['target_domain']}")
    print(f"Assets: {len(assets)}")
    print(f"DNS resolved: {resolved}")


if __name__ == "__main__":
    main()
