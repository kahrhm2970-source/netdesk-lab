"""NetDesk Lab: offline IPv4 LAN plan audit. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
from ipaddress import IPv4Address, IPv4Network
import json
from pathlib import Path
import sys

VERSION = "1.0.0"
MAX_BYTES = 1_048_576


class PlanError(ValueError):
    """A malformed or unsupported plan, distinct from a valid but faulty plan."""


def fields(value, required, optional, where):
    if not isinstance(value, dict):
        raise PlanError(f"{where}: expected an object")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        raise PlanError(f"{where}: missing={sorted(missing)}, unknown={sorted(extra)}")


def label(value, where):
    if not isinstance(value, str) or not value.strip() or len(value) > 120:
        raise PlanError(f"{where}: expected non-empty text, maximum 120 characters")
    return value.strip()


def vlan_id(value, where):
    if type(value) is not int or not 1 <= value <= 4094:
        raise PlanError(f"{where}: VLAN ID must be an integer from 1 to 4094")
    return value


def address(value, where):
    if not isinstance(value, str):
        raise PlanError(f"{where}: expected an IPv4 address string")
    try:
        return IPv4Address(value)
    except ValueError as exc:
        raise PlanError(f"{where}: invalid IPv4 address: {value}") from exc


def parse_plan(data):
    """Validate schema and types. Semantic network faults are audited separately."""
    fields(data, ["site", "vlans", "devices"], [], "plan")
    site = label(data["site"], "site")
    vlans, devices = [], []
    if not isinstance(data["vlans"], list) or not 1 <= len(data["vlans"]) <= 256:
        raise PlanError("vlans: expected 1–256 LAN VLANs")
    if not isinstance(data["devices"], list) or len(data["devices"]) > 10000:
        raise PlanError("devices: expected a list of at most 10000 static devices")
    ids, names = set(), set()
    for i, item in enumerate(data["vlans"]):
        where = f"vlans[{i}]"
        fields(item, ["id", "name", "subnet", "gateway"], ["dhcp"], where)
        vid = vlan_id(item["id"], where)
        if vid in ids:
            raise PlanError(f"{where}: duplicate VLAN ID {vid}")
        ids.add(vid)
        if not isinstance(item["subnet"], str) or "/" not in item["subnet"]:
            raise PlanError(f"{where}: subnet must include a prefix or netmask")
        try:
            network = IPv4Network(item["subnet"], strict=True)
        except ValueError as exc:
            raise PlanError(f"{where}: invalid canonical IPv4 subnet: {item['subnet']}") from exc
        if network.prefixlen > 30:
            raise PlanError(f"{where}: /31 and /32 are outside this LAN-only model")
        pool = item.get("dhcp")
        if pool is not None:
            fields(pool, ["start", "end"], [], where + ".dhcp")
            pool = (address(pool["start"], where), address(pool["end"], where))
        vlans.append({"id": vid, "name": label(item["name"], where),
                      "subnet": network, "gateway": address(item["gateway"], where),
                      "dhcp": pool})
    for i, item in enumerate(data["devices"]):
        where = f"devices[{i}]"
        fields(item, ["name", "vlan_id", "ip"], [], where)
        name = label(item["name"], where)
        if name.casefold() in names:
            raise PlanError(f"{where}: device names must be unique")
        names.add(name.casefold())
        devices.append({"name": name, "vlan_id": vlan_id(item["vlan_id"], where),
                        "ip": address(item["ip"], where)})
    return {"site": site, "vlans": vlans, "devices": devices}


def usable(ip, network):
    return ip in network and ip not in (network.network_address, network.broadcast_address)


def audit(plan):
    """Audit one routing domain. No sockets, device login, or configuration changes."""
    findings = []

    def add(code, entity, evidence, action):
        findings.append({"code": code, "severity": "error", "entity": entity,
                         "evidence": evidence, "action": action})

    vlans = {v["id"]: v for v in plan["vlans"]}
    pools = {}
    for i, v in enumerate(plan["vlans"]):
        entity = f"VLAN {v['id']} / {v['name']}"
        net, gateway, pool = v["subnet"], v["gateway"], v["dhcp"]
        if not usable(gateway, net):
            add("GATEWAY_INVALID", entity, f"{gateway} is not a usable host in {net}.",
                "Assign an unused host in the VLAN subnet as its gateway.")
        if pool:
            start, end = pool
            if start > end or not usable(start, net) or not usable(end, net):
                add("DHCP_RANGE_INVALID", entity, f"Pool {start}–{end} is invalid for {net}.",
                    "Use ordered usable host addresses inside the subnet.")
            else:
                pools[v["id"]] = pool
                if start <= gateway <= end:
                    add("GATEWAY_IN_DHCP", entity, f"Gateway {gateway} is inside {start}–{end}.",
                        "Exclude the gateway from the modeled DHCP pool.")
        for other in plan["vlans"][i + 1:]:
            if net.overlaps(other["subnet"]):
                add("SUBNET_OVERLAP", entity,
                    f"{net} overlaps VLAN {other['id']} ({other['subnet']}).",
                    "Allocate distinct subnets within this routing domain.")
    seen = {}
    for device in plan["devices"]:
        name, vid, ip = device["name"], device["vlan_id"], device["ip"]
        if vid not in vlans:
            add("UNKNOWN_VLAN", name, f"VLAN {vid} is not defined.",
                "Correct the device VLAN or define the missing VLAN.")
            continue
        v = vlans[vid]
        if not usable(ip, v["subnet"]):
            add("DEVICE_IP_INVALID", name, f"{ip} is not a usable host in VLAN {vid} ({v['subnet']}).",
                "Assign an unused host address in the correct VLAN subnet.")
        if ip == v["gateway"]:
            add("DEVICE_USES_GATEWAY", name, f"{ip} equals the gateway for VLAN {vid}.",
                "Give this endpoint a distinct static IP address.")
        key = (vid, ip)
        if key in seen:
            add("DUPLICATE_IP", name, f"{ip} is also assigned to {seen[key]} in VLAN {vid}.",
                "Assign distinct addresses and verify the DHCP lease/reservation records.")
        seen.setdefault(key, name)
        if vid in pools and pools[vid][0] <= ip <= pools[vid][1]:
            add("STATIC_IN_DHCP", name, f"Static IP {ip} is inside VLAN {vid}'s dynamic pool.",
                "Move the static address outside the pool or model a pool that excludes it.")
    return {"tool": "NetDesk Lab", "version": VERSION, "site": plan["site"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"vlans": len(vlans), "static_devices": len(plan["devices"]),
                        "findings": len(findings), "status": "review" if findings else "pass"},
            "findings": findings}


def html_report(report):
    """Escape all external data; no scripts, external fonts, or remote assets."""
    def h(value):
        return escape(str(value), quote=True)

    summary = report["summary"]
    counts = Counter(f["code"] for f in report["findings"])
    badges = "".join(f"<span>{h(k)} · {v}</span>" for k, v in sorted(counts.items()))
    rows = "".join("<tr>" + "".join(f"<td>{h(f[k])}</td>" for k in
                    ("code", "entity", "evidence", "action")) + "</tr>"
                   for f in report["findings"])
    if not rows:
        rows = '<tr><td colspan="4">No modeled addressing faults found. Live connectivity is not tested.</td></tr>'
    cards = "".join(f"<article><b>{h(value)}</b><p>{h(title)}</p></article>" for title, value in
                    [("VLANs", summary["vlans"]), ("Static devices", summary["static_devices"]),
                     ("Findings", summary["findings"]), ("Plan status", summary["status"].upper())])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>NetDesk Lab — {h(report['site'])}</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#0c1425;color:#eaf1ff;font:16px/1.6 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto;padding:40px 24px}}header{{border-bottom:1px solid #33415c;padding-bottom:24px}}
.eyebrow{{color:#55e0bc;font-weight:700;letter-spacing:2px}}h1{{font-size:42px;line-height:1.15;margin:12px 0}}
.muted{{color:#a9bbd6}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:28px 0}}
article{{background:#18243b;border:1px solid #33415c;border-radius:14px;padding:20px}}b{{font-size:30px}}
article p{{margin:0;color:#a9bbd6}}.tags{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}}
span{{border:1px solid #345a63;color:#6ce4c4;padding:5px 10px;border-radius:30px;font-size:12px}}
.table{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:750px;background:#121e33}}
th,td{{padding:16px;text-align:left;border-bottom:1px solid #33415c;vertical-align:top}}th{{color:#6ce4c4}}
footer{{margin-top:28px;color:#a9bbd6}}@media(max-width:650px){{.cards{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:32px}}}}
@media print{{body{{background:white;color:black}}article,table{{background:white}}.muted,article p,footer,th{{color:#33415c}}}}
</style></head><body><main><header><div class="eyebrow">NETDESK LAB / OFFLINE IPv4 AUDIT</div>
<h1>{h(report['site'])}</h1><p class="muted" lang="ar" dir="rtl">مراجعة خطة الشبكة · العناوين والبوابة وDHCP</p>
<p class="muted">Generated {h(report['generated_at'])} · v{h(report['version'])}</p></header>
<section class="cards" aria-label="Audit summary">{cards}</section><h2>Findings &amp; next actions</h2>
<div class="tags">{badges}</div><div class="table"><table><thead><tr><th>Rule</th><th>Asset</th><th>Evidence</th><th>Recommended action</th></tr></thead>
<tbody>{rows}</tbody></table></div><footer>Plan review only · Single routing domain · Static endpoints ·
No network scan or configuration changes. A PASS does not prove reachability, correct switch configuration, or security.</footer></main></body></html>'''


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PlanError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="JSON IPv4 LAN plan")
    parser.add_argument("--out", type=Path, default=Path("reports"), help="Output directory")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    try:
        # Read at most the input limit plus one byte, including for streams/special files.
        with args.plan.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise PlanError("Plan exceeds 1 MiB")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=reject_duplicates)
        report = audit(parse_plan(data))
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "audit.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.out / "audit.html").write_text(html_report(report), encoding="utf-8")
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        print(f"Input/output error: {exc}", file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f"{summary['status'].upper()} | {summary['vlans']} VLANs | "
          f"{summary['static_devices']} static devices | {summary['findings']} findings")
    print(f"Reports: {args.out / 'audit.html'} and {args.out / 'audit.json'}")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
