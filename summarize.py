#!/usr/bin/env python3
# Prints the detection results: projects scanned per target kind, verified copies per carrier and library
# (copies, projects, distinct versions), and every outcome status. Writes results/copies_by_library.csv.
import os, csv, json, glob, argparse, collections

ap = argparse.ArgumentParser()
ap.add_argument("--copies", default="results/copies")
ap.add_argument("--kind", choices=["image", "release", "maven"])
a = ap.parse_args()

summaries = [s for s in (json.load(open(f)) for f in sorted(glob.glob(os.path.join(a.copies, "*", "summary.json")))) if not a.kind or s["kind"] == a.kind]
kept = {s["project"] for s in summaries}
rows = [r for r in csv.DictReader(open(os.path.join(a.copies, "all_findings.csv"))) if r["project"] in kept]
verified = [r for r in rows if r["status"] == "verified"]

print(f"projects scanned: {len(summaries)} ({', '.join(f'{k} {v}' for k, v in sorted(collections.Counter(s['kind'] for s in summaries).items()))})")
print(f"projects with lookup errors: {', '.join(s['project'] for s in summaries if not s['complete']) or 'none'}")
print(f"java runtimes: {sum(len(s['java_runtimes']) for s in summaries)} in {sum(bool(s['java_runtimes']) for s in summaries)} projects; "
      f"native files in archives: {sum(s['native_files_in_archives'] for s in summaries)}")
print(f"verified copies: {len(verified)} in {len({(r['project'], r['file']) for r in verified})} files, "
      f"{len({r['project'] for r in verified})} projects, {len({r['library'] for r in verified})} libraries, "
      f"{len({(r['library'], r['version']) for r in verified})} library versions")

table = []
groups = collections.defaultdict(list)
for r in verified:
    groups[(r["carrier"], r["library"])].append(r)
for (c, l), rs in sorted(groups.items(), key=lambda x: (x[0][0], -len(x[1]))):
    table.append({"carrier": c, "library": l, "copies": len(rs), "projects": len({r["project"] for r in rs}),
                  "versions": len({r["version"] for r in rs}), "version_list": " ".join(sorted({r["version"] for r in rs}))})
with open(os.path.join(os.path.dirname(a.copies.rstrip("/")) or ".", f"copies_by_library{'_' + a.kind if a.kind else ''}.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["carrier", "library", "copies", "projects", "versions", "version_list"])
    w.writeheader()
    w.writerows(table)
print("\ncarrier        library     copies projects versions")
for t in table:
    print(f"{t['carrier']:<15}{t['library']:<12}{t['copies']:>6}{t['projects']:>9}{t['versions']:>9}")
print("\noutcomes:")
for s, n in collections.Counter(r["status"].split(" (")[0] for r in rows).most_common():
    print(f"  {n:>5}  {s}")
