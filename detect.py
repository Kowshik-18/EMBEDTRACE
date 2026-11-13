#!/usr/bin/env python3
# Step 1 of the study: runs EmbedTrace on every target in datasets/projects.csv and writes, per project,
# results/copies/<project>/findings.csv, summary.json, and unreadable_entries.json. It detects and verifies copies only; it reads no SBOM.
import os, sys, csv, json, shutil, argparse, traceback
from embedtrace import fetch, ospkg, locate, java_runtime, java_archive
from embedtrace.util import write_json, read_json, LookupFailed

COLUMNS = ["project", "target", "carrier", "file", "file_sha256", "library", "version", "status",
           "identity_source", "build_spec_source", "symbol_evidence", "version_source"]


def write_csv(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


def error_row(base, e):
    return dict(base, status=f"unresolved: lookup error ({type(e).__name__}: {str(e)[:120]})")


def scan(p, out_root, force=False):
    out = os.path.join(out_root, p["project"])
    old = read_json(os.path.join(out, "summary.json"))
    if old and not force and old.get("target") == p["target"] and old.get("complete"):
        print(f"[skip] {p['project']} already scanned", flush=True)
        return
    os.makedirs(out, exist_ok=True)
    print(f"[1] {p['project']}: materialize {p['kind']} {p['target']}", flush=True)
    t = fetch.materialize(p["kind"], p["target"], p["project"])
    try:
        print("[2] OS package ownership", flush=True)
        owned, dbs = ospkg.owned(t["rootfs"], t["links"])
        print("[3] locate candidates", flush=True)
        runtimes = locate.java_runtimes(t["rootfs"], t["links"], owned)
        natives, skipped = locate.archive_natives(t["rootfs"], t["links"], owned, [r["home"] for r in runtimes])
        print(f"    java runtimes {len(runtimes)}, runtime ELF files {sum(len(r['elf']) for r in runtimes)}, "
              f"ELF files in archives {len(natives)}, unreadable archive entries {len(skipped)}", flush=True)
        print("[4] verify", flush=True)
        rows, errors = [], 0
        for r in runtimes:
            try:
                rows += java_runtime.find(r, t["config"])
            except Exception as e:
                errors += 1
                rows.append(error_row(java_runtime.base_row(r, "release", ""), e))
        for n in natives:
            try:
                rows += java_archive.find(n)
            except Exception as e:
                errors += 1
                rows.append(error_row({"carrier": "Java archive", "file": " > ".join(n["chain"]), "file_sha256": n["sha256"]}, e))
        write_json(os.path.join(out, "unreadable_entries.json"), skipped)
        for r in rows:
            r.update(project=p["project"], target=p["target"])
        write_csv(os.path.join(out, "findings.csv"), rows)
        summary = {"project": p["project"], "kind": p["kind"], "target": p["target"], "complete": errors == 0,
                   "lookup_errors": errors, **{k: t[k] for k in ("platform_digest", "artifact_digest") if k in t},
                   "unresolved_hard_links": t.get("unresolved_hard_links", []), "os_package_files": dbs,
                   "java_runtimes": [{"home": r["home"], "vendor": r["release"].get("IMPLEMENTOR"),
                                      "version": r["release"].get("JAVA_RUNTIME_VERSION"), "libc": r["libc"]} for r in runtimes],
                   "native_files_in_archives": len(natives), "unreadable_archive_entries": len(skipped),
                   "verified_copies": sum(r["status"] == "verified" for r in rows),
                   "unresolved": sum(r["status"].startswith("unresolved") for r in rows)}
        write_json(os.path.join(out, "summary.json"), summary)
        print(f"[5] {summary['verified_copies']} verified, {summary['unresolved']} unresolved, {errors} lookup errors -> {out}", flush=True)
    finally:
        if t["temporary"]:
            shutil.rmtree(t["rootfs"], ignore_errors=True)


def combine(out_root):
    rows = []
    for d in sorted(os.listdir(out_root)):
        f = os.path.join(out_root, d, "findings.csv")
        if os.path.exists(f):
            rows += list(csv.DictReader(open(f)))
    write_csv(os.path.join(out_root, "all_findings.csv"), rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", default="datasets/projects.csv")
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--kind", choices=["image", "release", "maven"])
    ap.add_argument("--out", default="results/copies")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    projects = [r for r in csv.DictReader(open(a.projects)) if (not a.only or r["project"] in a.only) and (not a.kind or r["kind"] == a.kind)]
    os.makedirs(a.out, exist_ok=True)
    failed = []
    for p in projects:
        try:
            scan(p, a.out, a.force)
        except Exception:
            failed.append(p["project"])
            print(f"FAILED {p['project']}\n{traceback.format_exc()}", flush=True)
    combine(a.out)
    with open(os.path.join(a.out, "failed.txt"), "w") as f:
        f.write("".join(x + "\n" for x in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
