#!/usr/bin/env python3
# Shows how each image target was pinned: resolves every image tag in projects.csv to its current digest
# with `crane digest` and reports whether the tag still points to the pinned digest (tags such as latest move).
import os, csv, subprocess

here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "projects.csv")
moved = 0
for r in csv.DictReader(open(here)):
    if r["kind"] != "image":
        continue
    pinned = r["target"].split("@", 1)[1]
    now = subprocess.run(["crane", "digest", r["tag"]], capture_output=True, text=True).stdout.strip()
    state = "same" if now == pinned else f"moved (now {now or 'unresolved'})"
    moved += now != pinned
    print(f"{r['project']:<18} {r['tag']:<45} {pinned[:19]}  {state}")
print(f"{moved} tags no longer point to the pinned digest; the study always uses the pinned digest.")
