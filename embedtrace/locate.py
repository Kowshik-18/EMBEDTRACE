# Finds candidate native code that no OS package owns: Java runtime homes (a directory with a
# `release` file that sets JAVA_VERSION) and x86-64 Linux ELF files inside Java archives, nested
# archives included. Entries that cannot be read are recorded with the reason.
import os, re, io, zipfile, hashlib
from .util import is_elf, is_linux_x86_64_elf, sha256, cache_path, write_atomic, sha256_file
from .ospkg import canonical

ARCHIVE = re.compile(r"\.(jar|war|ear|nar|zip|hpi|jpi|rar|kar|sar)$", re.I)
OTHER_OS = re.compile(r"(^|[/_.\-])(freebsd|openbsd|netbsd|bsd|dragonfly|dragonflybsd|sunos|solaris|illumos|aix|android|darwin|osx|macos|mac|windows|win|win32|win64|ios)($|[/_.\-])", re.I)
MAX_DEPTH = 6
MAX_ENTRY = 1 << 30


def walk_files(rootfs, links):
    for d, dirs, files in os.walk(rootfs, followlinks=False):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(d, f)
            if os.path.isfile(p) and not os.path.islink(p):
                yield p, canonical("/" + os.path.relpath(p, rootfs), links)


def read_release(path):
    out = {}
    for line in open(path, errors="ignore"):
        m = re.match(r'^(\w+)="?(.*?)"?\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def java_runtimes(rootfs, links, owned):
    homes = []
    for p, rel in walk_files(rootfs, links):
        if os.path.basename(p) == "release" and rel not in owned and "JAVA_VERSION" in read_release(p):
            homes.append((os.path.dirname(p), os.path.dirname(rel)))
    homes = [h for h in homes if not any(h[1].startswith(o[1] + "/") for o in homes if o is not h)]
    out = []
    for home, home_rel in homes:
        elfs, libc = {}, "glibc"
        for q, qrel in walk_files(home, {}):
            full = canonical(home_rel + qrel, links)
            if full in owned:
                continue
            with open(q, "rb") as fh:
                head = fh.read(8192)
            if is_elf(head):
                elfs[qrel.lstrip("/")] = q
                if b"ld-musl" in head:
                    libc = "musl"
        out.append({"home": home_rel, "release": read_release(os.path.join(home, "release")), "elf": elfs, "libc": libc})
    return out


def pom_gavs(zf):
    gavs = []
    for n in zf.namelist():
        if n.startswith("META-INF/maven/") and n.endswith("/pom.properties"):
            kv = dict(re.findall(r"^(\w+)=(.*)$", zf.read(n).decode(errors="ignore"), re.M))
            if {"groupId", "artifactId", "version"} <= kv.keys():
                gav = f"{kv['groupId'].strip()}:{kv['artifactId'].strip()}:{kv['version'].strip()}"
                if re.fullmatch(r"[\w.\-]+:[\w.\-]+:[\w.\-+]+", gav) and gav not in gavs:
                    gavs.append(gav)
    return gavs


def store_native(b):
    h = sha256(b)
    store = cache_path("natives", h + ".so")
    if not (os.path.exists(store) and sha256_file(store) == h):
        write_atomic(store, b, "wb")
    return h, store


def walk_archive(source, chain, levels, out, skipped, depth=0):
    if depth > MAX_DEPTH:
        skipped.append({"chain": chain, "reason": "nesting deeper than %d" % MAX_DEPTH})
        return
    try:
        zf = zipfile.ZipFile(source)
        names = zf.infolist()
    except Exception as e:
        if depth:
            skipped.append({"chain": chain, "reason": f"not readable as zip ({type(e).__name__})"})
        return
    sha1 = hashlib.sha1()
    if isinstance(source, str):
        with open(source, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                sha1.update(b)
    else:
        sha1.update(source.getvalue())
    level = {"path": chain[-1], "sha1": sha1.hexdigest(), "pom_gavs": pom_gavs(zf)}
    for info in names:
        n = info.filename
        if info.is_dir():
            continue
        nested = ARCHIVE.search(n)
        if not nested and (info.file_size < 64 or OTHER_OS.search(os.path.dirname(n)) or OTHER_OS.search(os.path.basename(n).replace("x86_64", "x86-64"))):
            continue
        if info.file_size > MAX_ENTRY:
            skipped.append({"chain": chain + [n], "reason": "entry larger than 1 GiB"})
            continue
        try:
            if nested:
                walk_archive(io.BytesIO(zf.read(info)), chain + [n], levels + [level], out, skipped, depth + 1)
                continue
            with zf.open(info) as f:
                head = f.read(64)
            if not is_linux_x86_64_elf(head + b"\0" * 64):
                continue
            b = zf.read(info)
            h, store = store_native(b)
            out.append({"chain": chain + [n], "entry": n, "sha256": h, "store": store, "archives": levels + [level]})
        except Exception as e:
            skipped.append({"chain": chain + [n], "reason": f"entry not readable ({type(e).__name__})"})


def archive_natives(rootfs, links, owned, runtime_homes):
    out, skipped = [], []
    for p, rel in walk_files(rootfs, links):
        if not ARCHIVE.search(p) or rel in owned or any(rel.startswith(h.rstrip("/") + "/") for h in runtime_homes):
            continue
        walk_archive(p, [rel], [], out, skipped)
    return out, skipped
