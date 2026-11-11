# NetDesk Lab | مختبر الدعم الفني والشبكات

**Offline IPv4 LAN plan auditor** — a practical portfolio project for IT Support / Help Desk / Network Technician roles.

**الحسين علي أبو طالب — Alhussin Ali Abutalib** · Network Systems Administration diploma, Jazan University.

مشروع تدريبي بُني بمساعدة أدوات الذكاء الاصطناعي لتحويل خطة شبكة إلى تقرير قابل للمراجعة. يربط بين Subnetting وVLAN وDHCP وتوثيق الأعطال. جميع بيانات الأمثلة افتراضية، ولا تمثل شبكة عميل أو تجربة عمل فعلية.

## What it does | فكرة المشروع

Reads a JSON plan for a small branch with Staff, Printers, and Cameras VLANs, checks addressing consistency, and writes a portable HTML report plus machine-readable JSON. Uses Python's standard library; no account, API key, package installation, or administrator privileges required.

| Check | What is flagged |
|---|---|
| `SUBNET_OVERLAP` | Overlapping VLAN subnets in one routing domain |
| `GATEWAY_INVALID` | Gateway outside the subnet, or network/broadcast address |
| `GATEWAY_IN_DHCP` | Gateway included in the modeled dynamic pool |
| `DHCP_RANGE_INVALID` | Reversed pool, out-of-subnet endpoints, network/broadcast endpoints |
| `DEVICE_IP_INVALID` | Static endpoint outside its VLAN or using network/broadcast address |
| `DEVICE_USES_GATEWAY` | Static endpoint assigned its VLAN gateway |
| `DUPLICATE_IP` | Multiple static endpoints share an IP within the same VLAN |
| `STATIC_IN_DHCP` | Static endpoint included in the dynamic pool |
| `UNKNOWN_VLAN` | Endpoint refers to an undefined VLAN |

## Quick start | التشغيل

Requires **Python 3.10 or newer**. Clone or download this repository, open a terminal in its folder, then:

```bash
python netdesk.py examples/healthy.json --out reports/healthy
python netdesk.py examples/broken.json --out reports/broken
python -m unittest discover -s tests -v
```

Use `python3` if your system uses that command. On Windows, `py -3` can replace `python`.
Open `reports/broken/audit.html` in any browser. The second command intentionally exits with code **1** because it finds faults; this is a successful audit, not an application failure.

| Exit | Meaning |
|---|---|
| `0` | No modeled addressing faults |
| `1` | Review required; reports generated |
| `2` | Malformed input, unsupported model, or file I/O error |

**Mobile / Codespaces:** open this repository in GitHub Codespaces, run the same commands in its terminal, then download the generated HTML using the Explorer file menu to view it on your phone. No port forwarding or public hosting is needed.

## Reproducible demo | تجربة قبل وبعد

| Plan | VLANs | Static devices | Findings |
|---|---:|---:|---:|
| `examples/broken.json` | 4 | 6 | 11 |
| `examples/healthy.json` | 3 | 6 | 0 |

The broken plan deliberately contains all nine rule categories, including two PCs sharing an address, an incorrect printer gateway, a camera using the gateway address, and an overlapping guest subnet. The healthy plan removes the unused guest VLAN and fixes the addressing. These are **synthetic plan results**, not measurements from real devices.

View the committed example outputs in [docs/demo-audit.json](docs/demo-audit.json) and download [docs/demo-audit.html](docs/demo-audit.html) for the styled report.

## Input contract

```json
{
  "site": "Training branch",
  "vlans": [
    {"id": 10, "name": "Staff", "subnet": "192.168.10.0/24",
     "gateway": "192.168.10.1",
     "dhcp": {"start": "192.168.10.100", "end": "192.168.10.199"}}
  ],
  "devices": [
    {"name": "PC-01", "vlan_id": 10, "ip": "192.168.10.10"}
  ]
}
```

- `devices` lists **static endpoints only**; do not add the gateway itself as an endpoint.
- Each VLAN has one IPv4 subnet, one gateway, and zero or one continuous dynamic pool. Omit `dhcp` or set it to `null` if absent.
- To model reservations/exclusions, adjust the modeled pool or omit it; the tool does not interpret server reservations or multiple pool segments.
- VLAN IDs: integers 1–4094, unique. Device names: unique ignoring case. Labels: 1–120 characters.
- Subnets must have a prefix/netmask and zero host bits. `/31` and `/32` are deliberately rejected because this is an endpoint LAN model, not a point-to-point model.
- Limits: 1 MiB JSON, 256 VLANs, 10000 static endpoints. Duplicate JSON keys and unknown fields are rejected to catch typos.

## Scope and limitations

The tool reviews a supplied plan **offline**. It does not scan a network, verify live DHCP, prove VLAN isolation, test DNS, inspect switch ports/ACLs, change configuration, or establish network security. PASS means only that these rules found no faults in the input. Overlapping subnets are considered faults in this single-routing-domain model; separate VRFs are not supported. IPv6, lease discovery, multiple gateways, and DHCP exclusions are future extensions.

Reports include the supplied labels and IP addresses. Keep real customer plans and generated reports private. Only fictional examples are committed here. HTML content is escaped and uses no JavaScript or remote assets. A failed run can leave reports from an earlier run in the selected output directory; check the exit code and report timestamp.

## Engineering and validation

`parse_plan()` validates input → `audit()` creates evidence and recommended actions → `html_report()` renders escaped output → CLI writes HTML/JSON and returns a documented status.

17 automated tests cover expected demo results, boundary addresses, overlapping/adjacent networks, DHCP boundaries, duplicate identifiers, input failures, size limits, CLI exit codes, and HTML escaping. Run them using the command above. The GitHub Actions workflow is configured for Python 3.10, 3.12, and 3.13; check the Actions tab for actual remote run status.

## Explain it in an interview

ابدأ بالمشكلة: «قبل تطبيق خطة الشبكة أحتاج أتأكد من اتساق العناوين والبوابة وDHCP». شغّل المثال المعطوب، واشرح دليل تعارض عنوانين ثم إجراء التصحيح، وبعدها شغّل الخطة السليمة. وضّح أن نجاح المراجعة لا يثبت الاتصال الفعلي، وأن التحقق الميداني يشمل إعدادات العميل والسويتش وسجلات DHCP.

See [Arabic troubleshooting runbook](docs/RUNBOOK_AR.md) and [five-minute demonstration](docs/DEMO_AR.md).

## Primary references

- [Python — ipaddress](https://docs.python.org/3/library/ipaddress.html): address membership, network/broadcast boundaries, and overlap operations.
- [Microsoft — ipconfig](https://learn.microsoft.com/en-gb/windows-server/administration/windows-commands/ipconfig): inspecting Windows IP configuration and DHCP details for the manual runbook.

AI assistance was used to prepare implementation, tests, and documentation. This is an educational portfolio, not a claim of production deployment or commercial work experience.
