#!/usr/bin/env python3
# Step 3 of the study: checks, for every verified copy in results/copies/all_findings.csv, whether each generated
# SBOM in results/sboms/<project>/ lists the copied library at the copy's file, lists it elsewhere, or lists only the
# carrier. Output: results/comparison.csv and a printed summary per generator.
import os, re, sys, csv, gzip, json, argparse, collections
from urllib.parse import unquote

ALIAS = {"zlib": ["zlib", "libz", "zlib1g", "madler/zlib"], "libpng": ["libpng", "libpng16", "libpng16-16"],
         "libjpeg": ["libjpeg", "libjpeg-turbo", "libjpeg62-turbo", "libjpeg8", "ijg-libjpeg"],
         "jpeg": ["jpeg", "libjpeg", "libjpeg-turbo", "libjpeg62-turbo", "libjpeg8", "ijg-libjpeg"],
         "freetype": ["freetype", "freetype2", "libfreetype", "libfreetype6", "freetype-libs"],
         "lcms": ["lcms", "lcms2", "liblcms2", "liblcms2-2", "little-cms"], "harfbuzz": ["harfbuzz", "libharfbuzz", "libharfbuzz0b"],
         "giflib": ["giflib", "libgif", "libgif7"], "libffi": ["libffi", "libffi8", "libffi7"],
         "lz4": ["lz4", "liblz4", "liblz4-1", "lz4-libs"], "zstd": ["zstd", "libzstd", "libzstd1", "zstd-libs"],
         "snappy": ["snappy", "libsnappy", "libsnappy1v5"], "bzip2": ["bzip2", "libbz2", "libbz2-1.0"],
         "aws-lc": ["aws-lc"], "boringssl": ["boringssl"]}
OS_PURL = ("pkg:apk/", "pkg:deb/", "pkg:rpm/", "pkg:alpm/")
PATH_PROPS = ("syft:location:", "syft:metadata:virtualPath", "aquasecurity:trivy:FilePath", "SrcFile")


def components(path):
    try:
        with gzip.open(path, "rt") as f:
            d = json.load(f)
    except (OSError, ValueError, EOFError):
        return None
    out, stack = [], list(d.get("components", []) or [])
    while stack:
        c = stack.pop()
        stack += c.get("components", []) or []
        locs = [p.get("value", "") for p in c.get("properties", []) or [] if p.get("name", "").startswith(PATH_PROPS)]
        locs += [o.get("location", "") for o in (c.get("evidence") or {}).get("occurrences", []) or []]
        purl = c.get("purl") or ""
        if "path=" in purl:
            locs.append(unquote(purl.split("path=")[1].split("&")[0]))
        if c.get("type") == "file" or c.get("name", "").startswith("/"):
            locs.append(c.get("name", ""))
        out.append({"name": c.get("name", ""), "version": c.get("version", ""), "purl": purl,
                    "src": any(p.get("name") == "SrcFile" for p in c.get("properties", []) or []), "locs": [l for l in locs if l]})
    return out


def norm(loc, prefix):
    if prefix and loc.startswith(prefix):
        loc = loc[len(prefix):]
    loc = loc.replace("!/", ":")
    return ["/" + p.strip("/") for p in loc.split(":") if p.strip("/")]


def names_lib(c, lib):
    names = {c["name"].lower().split("/")[-1]}
    m = re.match(r"pkg:[^/]+/(?:[^/@]+/)*([^/@?]+)", c["purl"])
    if m:
        names.add(unquote(m.group(1)).lower())
    return bool(names & set(ALIAS.get(lib, [lib])))


def at_carrier(c, chain, prefix):
    carrier = chain if len(chain) == 1 else chain[:-1]
    for loc in c["locs"]:
        parts = norm(loc, prefix)
        if not parts:
            continue
        if c["src"] and os.path.basename(parts[-1]) == os.path.basename(carrier[-1]):
            return True
        if parts[0] != carrier[0]:
            continue
        if len(carrier) == 1 and len(parts) == 1:
            return True
        if len(carrier) > 1 and len(parts) > 1 and os.path.basename(parts[-1]) == os.path.basename(carrier[-1]):
            return True
    return False


def at_file(c, chain, prefix):
    return len(chain) == 1 and any(norm(l, prefix) == [chain[0]] for l in c["locs"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--copies", default="results/copies/all_findings.csv")
    ap.add_argument("--sboms", default="results/sboms")
    ap.add_argument("--out", default="results/comparison.csv")
    ap.add_argument("--projects", default="datasets/projects.csv")
    ap.add_argument("--kind", choices=["image", "release", "maven"])
    a = ap.parse_args()
    kinds = {p["project"]: p["kind"] for p in csv.DictReader(open(a.projects))}
    copies = [r for r in csv.DictReader(open(a.copies)) if r["status"] == "verified" and (not a.kind or kinds.get(r["project"]) == a.kind)]
    cache, rows = {}, []
    for r in copies:
        meta = json.load(open(os.path.join(a.sboms, r["project"], "meta.json"))) if os.path.exists(os.path.join(a.sboms, r["project"], "meta.json")) else {}
        if meta.get("target") != r["target"]:
            print(f"no SBOMs for {r['project']} at {r['target']}", file=sys.stderr)
            continue
        chain = ["/" + p.strip().strip("/") for p in r["file"].split(" > ")]
        for g in ("syft", "trivy", "cdxgen"):
            k = (r["project"], g)
            if k not in cache:
                cache[k] = components(os.path.join(a.sboms, r["project"], f"{g}.cdx.json.gz"))
            comps = cache[k]
            if comps is None:
                continue
            prefix = meta.get("rootfs_prefix", "")
            libc = [c for c in comps if names_lib(c, r["library"])]
            at = [c for c in libc if at_carrier(c, chain, prefix) or at_file(c, chain, prefix)]
            elsewhere = [c for c in libc if c not in at]
            carrier = [c for c in comps if at_carrier(c, chain, prefix) or at_file(c, chain, prefix)]
            rows.append({"project": r["project"], "carrier": r["carrier"], "file": r["file"], "library": r["library"],
                         "version": r["version"], "generator": g,
                         "library_at_copy": "; ".join(f"{c['name']}@{c['version']}" for c in at),
                         "library_elsewhere": "; ".join(sorted({f"{c['name']}@{c['version']}" + (" (OS package)" if c["purl"].startswith(OS_PURL) else "") for c in elsewhere})),
                         "carrier_components": "; ".join(sorted({f"{c['name'].rsplit('/', 1)[-1]}@{c['version']}" for c in carrier}))[:300]})
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["project"])
        w.writeheader()
        w.writerows(rows)
    print(f"verified copies: {len(copies)} in {len({r['project'] for r in copies})} projects")
    for g in ("syft", "trivy", "cdxgen"):
        gr = [x for x in rows if x["generator"] == g]
        n = len(gr)
        if not n:
            continue
        c = collections.Counter()
        for x in gr:
            c["library at copy"] += bool(x["library_at_copy"])
            c["library only elsewhere"] += not x["library_at_copy"] and bool(x["library_elsewhere"])
            c["carrier listed"] += bool(x["carrier_components"])
            c["carrier listed (Java archive)"] += bool(x["carrier_components"]) and x["carrier"] == "Java archive"
            c["carrier listed (Java runtime)"] += bool(x["carrier_components"]) and x["carrier"] == "Java runtime"
        print(f"{g:<7} copies {n:>4}: " + ", ".join(f"{k} {v}" for k, v in c.items()))


if __name__ == "__main__":
    main()
