# Lists the files that an OS package manager (dpkg, apk, rpm) owns in a target tree.
# Paths are resolved through the image's symbolic links, so merged-/usr layouts match the real files.
import os, re, glob, posixpath
from .util import sh


def canonical(path, links, hops=40):
    parts = [p for p in path.split("/") if p]
    out = "/"
    i = 0
    while i < len(parts):
        cur = posixpath.join(out, parts[i])
        if cur in links and hops > 0:
            hops -= 1
            t = links[cur]
            t = t if t.startswith("/") else posixpath.join(out, t)
            t = posixpath.normpath(t)
            parts = [p for p in t.split("/") if p] + parts[i + 1:]
            out, i = "/", 0
            continue
        out, i = cur, i + 1
    return posixpath.normpath(out)


def dpkg_paths(rootfs):
    paths = []
    for f in glob.glob(rootfs + "/var/lib/dpkg/info/*.list"):
        paths += [l.strip() for l in open(f, errors="ignore") if l.strip()]
    for f in glob.glob(rootfs + "/var/lib/dpkg/info/*.md5sums") + glob.glob(rootfs + "/var/lib/dpkg/status.d/*.md5sums"):
        paths += ["/" + l.split(None, 1)[1].strip() for l in open(f, errors="ignore") if len(l.split(None, 1)) == 2]
    return paths


def apk_paths(rootfs):
    db, paths, d = rootfs + "/lib/apk/db/installed", [], ""
    if not os.path.exists(db):
        return paths
    for line in open(db, errors="ignore"):
        if line.startswith("F:"):
            d = line[2:].strip()
        elif line.startswith("R:"):
            paths.append("/" + posixpath.join(d, line[2:].strip()))
    return paths


def rpm_paths(rootfs):
    if not any(os.path.exists(rootfs + p) for p in ("/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/rpmdb.sqlite")):
        return None
    r = sh("rpm", "--root", rootfs, "-qal")
    if r.returncode:
        raise RuntimeError("rpm database present but the rpm command cannot read it")
    return [l.strip() for l in r.stdout.splitlines() if l.startswith("/")]


def owned(rootfs, links):
    found = {"dpkg": dpkg_paths(rootfs), "apk": apk_paths(rootfs), "rpm": rpm_paths(rootfs) or []}
    paths = {canonical(p, links) for ps in found.values() for p in ps}
    return paths, {k: len(v) for k, v in found.items() if v}
