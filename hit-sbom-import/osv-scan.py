#!/usr/bin/env python3
"""
osv-scan.py — OSV.dev vulnerability scanner for iTop SBOM components.

Fetches every SBOMComponent from iTop, queries OSV.dev in parallel,
then writes the results back to iTop's vuln_* fields.

Requirements:
    pip install requests cvss

Usage:
    python3 osv-scan.py
    python3 osv-scan.py --url http://13.53.124.74/itop --user sbom --pass 'password'
    python3 osv-scan.py --dry-run          # scan but skip writing back to iTop
    python3 osv-scan.py --workers 20       # parallel OSV threads (default: 10)
    python3 osv-scan.py --only-changed     # skip components whose cache is already current
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests
try:
    from cvss import CVSS3, CVSS2
    _CVSS_AVAILABLE = True
except ImportError:
    _CVSS_AVAILABLE = False

# ── Load .live-env defaults ───────────────────────────────────────────────────
def _load_live_env():
    """Parse .live-env from the same directory as this script."""
    env_file = Path(__file__).parent / ".live-env"
    vals = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                vals[k.strip()] = v.strip().strip('"')
    return vals

_env = _load_live_env()

DEFAULT_URL  = _env.get("ITOP_URL",       "http://13.53.124.74/itop")
DEFAULT_USER = _env.get("ITOP_REST_USER", "sbom")
DEFAULT_PASS = _env.get("ITOP_REST_PASS", "password")
OSV_API      = "https://api.osv.dev/v1/query"
OSV_BATCH    = "https://api.osv.dev/v1/querybatch"

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}

# ── iTop REST helpers ─────────────────────────────────────────────────────────

def itop_request(session, base_url, user, password, payload):
    """POST a JSON payload to the iTop REST API and return the parsed response."""
    r = session.post(
        f"{base_url}/webservices/rest.php?version=1.3",
        data={
            "auth_user": user,
            "auth_pwd":  password,
            "json_data": json.dumps(payload),
        },
        timeout=60,
    )
    r.raise_for_status()
    j = r.json()
    if j.get("code") != 0:
        raise RuntimeError(f"iTop API error: {j.get('message')}")
    return j


def fetch_components(session, base_url, user, password):
    """Return all SBOMComponent objects that have a non-empty PURL."""
    print("Fetching SBOM components from iTop…", flush=True)
    j = itop_request(session, base_url, user, password, {
        "operation":     "core/get",
        "class":         "SBOMComponent",
        "key":           "SELECT SBOMComponent",
        "output_fields": (
            "name,version,purl,"
            "vuln_severity,vuln_ids,vuln_cvss_score,vuln_attack_vector,vuln_last_scanned"
        ),
        "limit": 5000,
    })
    objects = j.get("objects") or {}
    components = []
    for key, obj in objects.items():
        f = obj["fields"]
        purl = (f.get("purl") or "").strip()
        if not purl:
            continue
        components.append({
            "key":            key,                              # e.g. "SBOMComponent::42"
            "id":             key.split("::")[1],
            "name":           f.get("name", ""),
            "version":        f.get("version", ""),
            "purl":           purl,
            "cached_sev":     (f.get("vuln_severity") or "none").lower(),
            "cached_ids":     (f.get("vuln_ids") or "").strip(),
            "cached_score":   float(f.get("vuln_cvss_score") or 0),
            "cached_av":      (f.get("vuln_attack_vector") or "").lower(),
            "cached_scanned": f.get("vuln_last_scanned") or "",
        })
    total = len(j.get("objects") or {})
    print(f"  Found {total} components total, {len(components)} with a PURL.\n")
    return components


def update_component(session, base_url, user, password, comp_id, fields):
    """Write vuln_* fields back to one SBOMComponent object in iTop."""
    return itop_request(session, base_url, user, password, {
        "operation":     "core/update",
        "class":         "SBOMComponent",
        "key":           f"SELECT SBOMComponent WHERE id = {comp_id}",
        "comment":       "OSV.dev vulnerability scan",
        "fields":        fields,
        "output_fields": "id",
    })


# ── OSV.dev helpers ───────────────────────────────────────────────────────────

def query_osv_single(purl, session):
    """Query OSV.dev for a single PURL. Returns list of vuln dicts."""
    try:
        r = session.post(
            OSV_API,
            json={"package": {"purl": purl}},
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("vulns") or []
    except Exception as e:
        return []  # network blip — treat as no result


def parse_vulns(raw_vulns):
    """
    Convert the raw OSV response into a compact list of:
        { id, severity, score, attack_vector }
    Returns an empty list if there are no vulnerabilities.
    """
    results = []
    for v in raw_vulns:
        vid = v.get("id", "UNKNOWN")

        # Try CVSS v3 first, then v2
        sev_entry = next(
            (s for s in (v.get("severity") or []) if s.get("type") == "CVSS_V3"),
            next(iter(v.get("severity") or []), None),
        )
        score = 0.0
        av    = "unknown"
        if sev_entry:
            vector = sev_entry.get("score", "")
            av = _av_from_vector(vector)
            score = _score_from_vector(vector)

        # Severity from database_specific or derived from score.
        # Normalise OSV values (MODERATE → MEDIUM) to match the iTop enum.
        db_sev = (v.get("database_specific") or {}).get("severity", "")
        severity = _normalise_sev(db_sev.upper()) if db_sev else _score_to_sev(score)

        results.append({
            "id":            vid,
            "severity":      severity,
            "score":         score,
            "attack_vector": av,
        })
    return results


def _av_from_vector(cvss_vector):
    """Extract attack vector from a CVSS vector string."""
    for part in cvss_vector.split("/"):
        if part.startswith("AV:"):
            return {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}.get(
                part[3:], "unknown"
            )
    return "unknown"


def _score_from_vector(vector):
    """Compute the numeric CVSS base score from a vector string using the cvss library."""
    if not vector:
        return 0.0
    if _CVSS_AVAILABLE:
        try:
            if vector.startswith("CVSS:3"):
                return float(CVSS3(vector).base_score)
            if vector.startswith("CVSS:2") or vector.startswith("AV:"):
                return float(CVSS2(vector).base_score)
        except Exception:
            pass
    return 0.0


def _normalise_sev(s):
    """Map OSV severity strings to the iTop enum values (lowercase)."""
    return {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MODERATE": "MEDIUM",   # OSV uses MODERATE; iTop enum uses MEDIUM
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
        "NONE":     "NONE",
    }.get(s, "MEDIUM")  # default unknown → MEDIUM to be safe

def _score_to_sev(score):
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


def _top_vuln(vulns):
    """Return the single highest-severity vuln from a list."""
    return max(vulns, key=lambda v: (SEV_RANK.get(v["severity"], 0), v["score"]))


# ── Main scan loop ────────────────────────────────────────────────────────────

def scan_component(comp, osv_session):
    """Run the OSV query for one component. Returns (comp, vulns_list)."""
    raw = query_osv_single(comp["purl"], osv_session)
    vulns = parse_vulns(raw)
    return comp, vulns


def run_scan(args):
    base_url = args.url.rstrip("/")

    itop_session = requests.Session()
    osv_session  = requests.Session()

    # ── Verify iTop credentials ───────────────────────────────────────────────
    print(f"Connecting to iTop at {base_url} …", flush=True)
    try:
        j = itop_request(itop_session, base_url, args.user, getattr(args, 'pass'), {
            "operation": "list_operations"
        })
        print(f"  Connected. iTop API version {j.get('version','?')}, "
              f"{j.get('message','')}\n")
    except Exception as e:
        print(f"ERROR: Cannot connect to iTop: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Fetch components ──────────────────────────────────────────────────────
    try:
        components = fetch_components(itop_session, base_url, args.user, getattr(args, 'pass'))
    except Exception as e:
        print(f"ERROR fetching components: {e}", file=sys.stderr)
        # If the vuln_* fields don't exist yet, give a clear hint
        if "invalid attribute" in str(e).lower() or "output_fields" in str(e).lower():
            print(
                "\nHint: the vuln_* fields don't exist in iTop yet.\n"
                "Run iTop's setup/toolkit to apply the updated datamodel first,\n"
                "or re-run with --no-cache to skip reading/writing the cache fields.",
                file=sys.stderr,
            )
        sys.exit(1)

    if not components:
        print("No components with PURLs found. Nothing to do.")
        return

    # ── OSV scan in parallel ──────────────────────────────────────────────────
    total    = len(components)
    done     = 0
    t_start  = time.time()

    results_vuln  = []   # (comp, vulns)
    results_clean = []   # components with no CVEs

    print(f"Scanning {total} components against OSV.dev "
          f"({args.workers} parallel workers)…\n")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_component, comp, osv_session): comp
            for comp in components
        }
        for future in as_completed(futures):
            comp, vulns = future.result()
            done += 1

            # Progress line
            pct  = done / total * 100
            bar  = ("█" * int(pct / 4)).ljust(25)
            elapsed = time.time() - t_start
            eta  = (elapsed / done * (total - done)) if done else 0
            print(
                f"\r  [{bar}] {done}/{total}  {pct:5.1f}%  ETA {eta:4.0f}s",
                end="", flush=True,
            )

            if vulns:
                results_vuln.append((comp, vulns))
            else:
                results_clean.append(comp)

    elapsed = time.time() - t_start
    print(f"\n\nScan complete in {elapsed:.1f}s.")
    print(f"  Vulnerable : {len(results_vuln)}")
    print(f"  Clean      : {len(results_clean)}")

    # ── Print findings ────────────────────────────────────────────────────────
    if results_vuln:
        print("\n── Vulnerabilities found ──────────────────────────────────────────")
        results_vuln.sort(
            key=lambda x: SEV_RANK.get(_top_vuln(x[1])["severity"], 0),
            reverse=True,
        )
        for comp, vulns in results_vuln:
            top = _top_vuln(vulns)
            ids = " ".join(v["id"] for v in vulns[:8])
            suffix = f" (+{len(vulns)-8} more)" if len(vulns) > 8 else ""
            print(
                f"  [{top['severity']:8s}] {comp['name']} {comp['version']}\n"
                f"           {ids}{suffix}\n"
                f"           AV:{top['attack_vector'].upper()}  PURL: {comp['purl']}"
            )
            print()

    # ── Write back to iTop ────────────────────────────────────────────────────
    if args.dry_run:
        print("--dry-run: skipping iTop updates.")
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Build the set of updates needed
    updates = []

    for comp, vulns in results_vuln:
        top     = _top_vuln(vulns)
        new_sev = top["severity"].lower()
        new_ids = " ".join(v["id"] for v in vulns)
        new_score = top["score"]
        new_av    = top["attack_vector"].lower()

        if (
            args.only_changed
            and comp["cached_sev"]   == new_sev
            and comp["cached_ids"]   == new_ids
            and comp["cached_score"] == new_score
        ):
            continue  # nothing changed

        updates.append((comp, {
            "vuln_severity":      new_sev,
            "vuln_ids":           new_ids,
            "vuln_cvss_score":    new_score,
            "vuln_attack_vector": new_av,
            "vuln_last_scanned":  now_str,
        }))

    for comp in results_clean:
        if comp["cached_sev"] == "none" and not comp["cached_ids"]:
            continue  # already clean in iTop, skip
        updates.append((comp, {
            "vuln_severity":      "none",
            "vuln_ids":           "",
            "vuln_cvss_score":    0,
            "vuln_attack_vector": "",
            "vuln_last_scanned":  now_str,
        }))

    if not updates:
        print("\nAll cached data is already up-to-date — nothing to write.")
        return

    print(f"\nWriting {len(updates)} updates to iTop…", flush=True)
    written  = 0
    errors   = 0

    for i, (comp, fields) in enumerate(updates, 1):
        pct = i / len(updates) * 100
        bar = ("█" * int(pct / 4)).ljust(25)
        print(f"\r  [{bar}] {i}/{len(updates)}  {pct:5.1f}%", end="", flush=True)
        try:
            update_component(
                itop_session, base_url, args.user, getattr(args, 'pass'),
                comp["id"], fields,
            )
            written += 1
        except Exception as e:
            errors += 1
            print(f"\n  WARN: failed to update {comp['name']} ({comp['id']}): {e}")

    print(f"\n\nDone. Wrote {written} records, {errors} errors.")

    if errors and "invalid attribute" in str(e).lower() if 'e' in dir() else False:
        print(
            "\nHint: if you're seeing 'invalid attribute code' errors for vuln_* fields,\n"
            "the datamodel hasn't been applied yet. Run iTop setup to deploy the new fields."
        )


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Scan iTop SBOM components against OSV.dev and cache results in iTop.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--url",          default=DEFAULT_URL,  help="iTop base URL")
    p.add_argument("--user",         default=DEFAULT_USER, help="iTop username")
    # 'pass' is a reserved keyword, use dest trick
    p.add_argument("--pass",         default=DEFAULT_PASS, dest="pass", help="iTop password")
    p.add_argument("--workers",      type=int, default=10, help="Parallel OSV threads (default: 10)")
    p.add_argument("--dry-run",      action="store_true",  help="Scan only, don't write to iTop")
    p.add_argument("--only-changed", action="store_true",  help="Skip components whose cache is already current")
    p.add_argument("--no-cache",     action="store_true",  help="Don't read or write vuln_* cache fields (useful before datamodel is applied)")

    args = p.parse_args()

    if args.no_cache:
        # Monkey-patch to not request or write the cache fields
        global fetch_components
        _orig_fetch = fetch_components
        def fetch_components_no_cache(session, base_url, user, password):
            print("Fetching SBOM components from iTop (no-cache mode)…", flush=True)
            j = itop_request(session, base_url, user, password, {
                "operation":     "core/get",
                "class":         "SBOMComponent",
                "key":           "SELECT SBOMComponent",
                "output_fields": "name,version,purl",
                "limit":         5000,
            })
            objects = j.get("objects") or {}
            components = []
            for key, obj in objects.items():
                f = obj["fields"]
                purl = (f.get("purl") or "").strip()
                if not purl:
                    continue
                components.append({
                    "key": key, "id": key.split("::")[1],
                    "name": f.get("name",""), "version": f.get("version",""),
                    "purl": purl,
                    "cached_sev": "none", "cached_ids": "",
                    "cached_score": 0.0, "cached_av": "", "cached_scanned": "",
                })
            print(f"  Found {len(components)} components with a PURL.\n")
            return components
        fetch_components = fetch_components_no_cache

        if args.dry_run is False:
            # In no-cache mode, don't attempt to write back either
            args.dry_run = True
            print("Note: --no-cache implies --dry-run (can't write without the vuln_* fields).\n")

    run_scan(args)


if __name__ == "__main__":
    main()
