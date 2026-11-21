#!/usr/bin/env python3
"""Run NetSecureOps offline audits against multiple saved device configurations."""
import argparse
import csv
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def safe_device_name(path):
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem).strip("._")
    return stem[:64] or "device"


def main():
    parser = argparse.ArgumentParser(description="Audit multiple saved configuration files using NetSecureOps.")
    parser.add_argument("configs", nargs="+", help="Configuration file paths (.txt, .cfg, .conf)")
    parser.add_argument("--out", default="reports/multi_device", help="Output directory")
    parser.add_argument("--auditor", default="src/auditor.py", help="Path to auditor.py")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    auditor = (root / args.auditor).resolve()
    if not auditor.is_file():
        print(f"ERROR: Auditor not found: {auditor}", file=sys.stderr)
        return 2

    configs = [Path(c).expanduser().resolve() for c in args.configs]
    missing = [p for p in configs if not p.is_file()]
    if missing:
        for path in missing:
            print(f"ERROR: Configuration not found: {path}", file=sys.stderr)
        return 2

    out_root = Path(args.out)
    if not out_root.is_absolute():
        out_root = root / out_root
    run_dir = out_root / ("run_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    run_dir.mkdir(parents=True, exist_ok=False)

    devices, used = [], set()
    for config in configs:
        base = safe_device_name(config)
        name, n = base, 2
        while name in used:
            name, n = f"{base}_{n}", n + 1
        used.add(name)
        device_out = run_dir / name
        proc = subprocess.run(
            [sys.executable, str(auditor), str(config), "--out", str(device_out)],
            capture_output=True, text=True, cwd=root
        )
        report_path = device_out / "audit_report.json"
        if proc.returncode != 0 or not report_path.is_file():
            devices.append({
                "device": name, "source_config": str(config), "status": "error",
                "error": (proc.stderr or proc.stdout or "Auditor failed.").strip()
            })
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            devices.append({
                "device": name, "source_config": str(config), "status": "error",
                "error": f"Could not read generated report: {exc}"
            })
            continue
        counts = {}
        for finding in report.get("findings", []):
            sev = str(finding.get("severity", "Unknown"))
            counts[sev] = counts.get(sev, 0) + 1
        devices.append({
            "device": name, "source_config": str(config), "status": "success",
            "report_path": str(report_path), "risk_score": report.get("risk_score", 0),
            "risk_label": report.get("risk_label", "Unknown"),
            "findings_count": len(report.get("findings", [])), "severity_counts": counts
        })

    successful = [d for d in devices if d["status"] == "success"]
    ranked = sorted(successful, key=lambda d: (-int(d.get("risk_score", 0)), d["device"].lower()))
    summary = {
        "tool": "NetSecureOps Multi-Device Audit", "version": "1.0.0",
        "run_time_utc": datetime.now(timezone.utc).isoformat(),
        "devices_requested": len(configs), "devices_successful": len(successful),
        "devices_failed": len(devices) - len(successful),
        "highest_risk_device": ranked[0]["device"] if ranked else None,
        "devices": devices,
        "limitations": [
            "Audits saved configuration files only; no live device connection is made.",
            "Risk scores are project heuristics, not CVSS scores.",
            "Validate findings against device model, IOS features and intended network policy."
        ]
    }
    (run_dir / "multi_device_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    columns = ["device", "source_config", "status", "risk_score", "risk_label", "findings_count",
               "critical", "high", "medium", "low", "info", "report_path", "error"]
    with (run_dir / "multi_device_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for d in devices:
            counts = d.get("severity_counts", {})
            writer.writerow({
                "device": d["device"], "source_config": d["source_config"], "status": d["status"],
                "risk_score": d.get("risk_score", ""), "risk_label": d.get("risk_label", ""),
                "findings_count": d.get("findings_count", ""),
                "critical": counts.get("Critical", 0), "high": counts.get("High", 0),
                "medium": counts.get("Medium", 0), "low": counts.get("Low", 0),
                "info": counts.get("Info", 0), "report_path": d.get("report_path", ""),
                "error": d.get("error", "")
            })
    print("\n=== NetSecureOps Multi-Device Audit ===")
    print(f"Devices requested : {summary['devices_requested']}")
    print(f"Successful        : {summary['devices_successful']}")
    print(f"Failed            : {summary['devices_failed']}")
    for d in ranked:
        print(f"  {d['device']}: score {d.get('risk_score', 0)}/100 ({d.get('risk_label', 'Unknown')}), findings={d.get('findings_count', 0)}")
    for d in devices:
        if d["status"] == "error":
            print(f"  ERROR {d['device']}: {d['error']}")
    print(f"\nSummary JSON: {run_dir / 'multi_device_summary.json'}")
    print(f"Summary CSV : {run_dir / 'multi_device_summary.csv'}")
    return 0 if not summary["devices_failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

