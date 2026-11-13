#!/usr/bin/env python3
# Step 2 of the study: generates SBOMs for every target in datasets/projects.csv with Syft, Trivy, and cdxgen,
# each run on the same materialized file tree. Output: results/sboms/<project>/<generator>.cdx.json.gz and meta.json.
import os, re, sys, csv, gzip, json, time, shutil, argparse, subprocess, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from embedtrace import fetch
from embedtrace.util import write_json, read_json

GENERATORS = {
    "syft": lambda root, out: ["syft", f"dir:{root}", "-q", "-o", f"cyclonedx-json={out}"],
    "trivy": lambda root, out: ["trivy", "rootfs", "--quiet", "--scanners", "vuln", "--format", "cyclonedx", "--output", out, root],
    "cdxgen": lambda root, out: ["cdxgen", "-t", "universal", "-r", "--no-install-deps", "-o", out, root],
}
VERSION = {"syft": ["syft", "version"], "trivy": ["trivy", "--version"], "cdxgen": ["cdxgen", "--version"]}


def version(g):
    try:
        out = subprocess.run(VERSION[g], capture_output=True, text=True, timeout=120).stdout
    except Exception:
        return None
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    m = re.search(r"(?:CycloneDX Generator|^Version:)\s*v?([\d.]+)", out, re.M)
    return m.group(1) if m else out.strip()[:40]


def valid(path):
    try:
        with gzip.open(path, "rt") as f:
            d = json.load(f)
    except (OSError, ValueError, EOFError):
        return False
    return isinstance(d, dict) and "components" in d


def generate(p, out_root, timeout, force):
    out = os.path.join(out_root, p["project"])
    meta = read_json(os.path.join(out, "meta.json")) or {}
    todo = [g for g in GENERATORS if force or meta.get("target") != p["target"] or not valid(os.path.join(out, f"{g}.cdx.json.gz"))]
    if not todo:
        print(f"[skip] {p['project']}", flush=True)
        return True
    os.makedirs(out, exist_ok=True)
    print(f"[1] {p['project']}: materialize {p['kind']} {p['target']}", flush=True)
    t = fetch.materialize(p["kind"], p["target"], p["project"])
    root = os.path.realpath(t["rootfs"])
    meta.update(project=p["project"], target=p["target"], rootfs_prefix=root, runs=meta.get("runs", {}))
    ok = True
    try:
        for g in todo:
            dest = os.path.join(out, f"{g}.cdx.json")
            packed = dest + ".gz"
            start = time.time()
            try:
                r = subprocess.run(GENERATORS[g](root, dest), capture_output=True, text=True, timeout=timeout)
                code, err = r.returncode, r.stderr[-300:]
            except subprocess.TimeoutExpired:
                code, err = "timeout", ""
            if os.path.exists(dest):
                with open(dest, "rb") as src, gzip.open(packed + ".tmp", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.replace(packed + ".tmp", packed)
                os.remove(dest)
            good = valid(packed)
            ok &= good
            meta["runs"][g] = {"version": version(g), "exit": code, "seconds": round(time.time() - start), "valid": good,
                               "command": " ".join(GENERATORS[g]("<root>", f"{g}.cdx.json")), "stderr_tail": "" if good else err}
            print(f"[2] {g}: exit {code}, valid {good}, {meta['runs'][g]['seconds']} s", flush=True)
    finally:
        write_json(os.path.join(out, "meta.json"), meta)
        if t["temporary"]:
            shutil.rmtree(t["rootfs"], ignore_errors=True)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", default="datasets/projects.csv")
    ap.add_argument("--only", nargs="*", default=[])
    ap.add_argument("--kind", choices=["image", "release", "maven"])
    ap.add_argument("--out", default="results/sboms")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    failed = []
    for p in csv.DictReader(open(a.projects)):
        if (a.only and p["project"] not in a.only) or (a.kind and p["kind"] != a.kind):
            continue
        try:
            if not generate(p, a.out, a.timeout, a.force):
                failed.append(p["project"])
        except Exception:
            failed.append(p["project"])
            print(f"FAILED {p['project']}\n{traceback.format_exc()}", flush=True)
    print(f"failed: {' '.join(failed) or 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
