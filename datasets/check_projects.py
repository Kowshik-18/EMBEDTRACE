#!/usr/bin/env python3
# Checks the project list: reads the 50 Apache Java projects ranked by Criticality Score in OpenRefactory's
# ose-metadata (pinned commit) and checks that datasets/projects.csv names the same projects and scores.
import os, re, csv, sys, urllib.request

COMMIT = "936dc9e6d33ce6fbb61aa3f9b67aba79fad2d4ce"
URL = f"https://raw.githubusercontent.com/OpenRefactory-Inc/ose-metadata/{COMMIT}/project-list.md"

text = urllib.request.urlopen(URL, timeout=60).read().decode()
ranked = []
for line in text.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) > 2 and re.fullmatch(r"0?\.\d+", cells[2]):
        ranked.append((cells[0], cells[1].rstrip("/").rsplit("/", 1)[-1], cells[2]))
ranked.sort(key=lambda r: -float(r[2]))
here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "projects.csv")
rows = list(csv.DictReader(open(here)))
mismatch = [(r["project"], p[1]) for r, p in zip(rows, ranked) if (r["project"], r["criticality_score"]) != (p[1], p[2])]
print(f"ose-metadata lists {len(ranked)} projects; projects.csv lists {len(rows)}; mismatches: {mismatch or 'none'}")
sys.exit(1 if mismatch or len(rows) != len(ranked) else 0)
