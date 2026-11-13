# Materializes one analysis target as a directory tree: a container image pinned by digest,
# an official binary release archive checked against its published checksum, or the jars that
# a project release published on Maven Central.
import os, re, json, shutil, tarfile, zipfile, posixpath, tempfile, subprocess
from concurrent.futures import ThreadPoolExecutor
from .util import CRANE, PLATFORM, sh, http, http_text, download, cache_path, LookupFailed, sha256_file

CENTRAL = "https://repo1.maven.org/maven2"
SKIP_JARS = re.compile(r"-(sources|javadoc|tests|test-sources|test-jar)\.jar$")


def clean_member(name):
    n = name[2:] if name.startswith("./") else name
    n = posixpath.normpath("/" + n.lstrip("/"))
    if n in ("/", "/.") or ".." in n.split("/"):
        return None
    return n


def inside(root, path):
    r = os.path.realpath(root)
    return os.path.realpath(path).startswith(r + os.sep)


def image_digest(ref):
    d = sh(CRANE, "digest", "--platform", PLATFORM, ref).stdout.strip()
    if not d.startswith("sha256:"):
        raise LookupFailed(f"cannot resolve {ref} for {PLATFORM}")
    return d


def image_config(ref):
    out = sh(CRANE, "config", "--platform", PLATFORM, ref).stdout
    return json.loads(out) if out else {}


def unpack_image(ref, rootfs):
    links, pending = {}, []
    p = subprocess.Popen([CRANE, "export", "--platform", PLATFORM, ref, "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with tarfile.open(fileobj=p.stdout, mode="r|") as tf:
        for m in tf:
            name = clean_member(m.name)
            if not name:
                continue
            dst = rootfs + name
            if m.issym():
                links[name] = m.linkname
            elif m.islnk():
                target = clean_member(m.linkname)
                if target:
                    pending.append((target, dst))
            elif m.isfile():
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.islink(dst) or not inside(rootfs, dst):
                    continue
                with open(dst, "wb") as w:
                    shutil.copyfileobj(tf.extractfile(m), w, 1 << 20)
    err = p.stderr.read().decode(errors="ignore")
    p.wait()
    if p.returncode:
        raise LookupFailed(f"crane export failed for {ref}: {err[-200:]}")
    unresolved = []
    for target, dst in pending:
        src = rootfs + target
        if os.path.isfile(src) and inside(rootfs, src) and inside(rootfs, dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.exists(dst):
                shutil.copyfile(src, dst)
        else:
            unresolved.append(dst[len(rootfs):])
    return links, unresolved


def published_digest(url):
    for algo, size in (("sha512", 128), ("sha256", 64)):
        t = http_text(url + "." + algo)
        if not t:
            continue
        t = re.sub(r"\S+\.(zip|tgz|gz|bz2|xz)\b:?", " ", t)
        h = "".join(re.findall(r"[0-9a-fA-F]+", re.sub(r"\s", "", t))).lower()
        if len(h) != size:
            raise LookupFailed(f"cannot parse .{algo} for {url}")
        return algo, h
    raise LookupFailed(f"no published checksum for {url}")


def file_digest(path, algo):
    import hashlib
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def unpack_archive(path, dest):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                name = clean_member(info.filename)
                if not name or info.is_dir() or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                out = dest + name
                if not inside(dest, out):
                    continue
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with z.open(info) as r, open(out, "wb") as w:
                    shutil.copyfileobj(r, w, 1 << 20)
    else:
        with tarfile.open(path) as tf:
            tf.extractall(dest, filter="data")


def fetch_release(url, rootfs):
    store = cache_path("releases", os.path.basename(url))
    algo, want = published_digest(url)
    if not (os.path.exists(store) and file_digest(store, algo) == want):
        if not download(url, store):
            raise LookupFailed(f"404 {url}")
    if file_digest(store, algo) != want:
        raise LookupFailed(f"{algo} mismatch for {url}")
    unpack_archive(store, rootfs)
    return f"{algo}:{want}"


def listing(url):
    t = http_text(url)
    return [] if t is None else [h.rstrip("/") for h in re.findall(r'href="([^"?#/][^"?#]*)"', t) if not h.startswith("..")]


def maven_jars(spec):
    groups, version = spec.rsplit("@", 1)
    gas = []
    for g in groups.split(","):
        if ":" in g:
            gas.append(tuple(g.split(":")))
        else:
            gas += [(g, a) for a in listing(f"{CENTRAL}/{g.replace('.', '/')}/") if not a.endswith((".xml", ".md5", ".sha1"))]

    def jars(ga):
        g, a = ga
        base = f"{CENTRAL}/{g.replace('.', '/')}/{a}/{version}/"
        return [(g, a, base + f) for f in listing(base) if f.endswith(".jar") and not SKIP_JARS.search(f)]

    with ThreadPoolExecutor(4) as ex:
        return version, [j for js in ex.map(jars, gas) for j in js]


def fetch_maven(spec, rootfs):
    version, jars = maven_jars(spec)
    if not jars:
        raise LookupFailed(f"no jars on Maven Central for {spec}")

    def get(j):
        g, a, url = j
        dest = os.path.join(rootfs, g, a, os.path.basename(url))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if not os.path.exists(dest) and not download(url, dest):
            raise LookupFailed(f"404 {url}")

    with ThreadPoolExecutor(4) as ex:
        list(ex.map(get, jars))
    return f"{len(jars)} jars at version {version}"


def materialize(kind, target, project):
    if kind == "image":
        if "@sha256:" not in target:
            raise LookupFailed(f"image target must be pinned by digest: {target}")
        rootfs = tempfile.mkdtemp(prefix="rootfs_", dir=cache_path("work", "x").rsplit("/", 1)[0])
        try:
            platform_digest = image_digest(target)
            for attempt in range(3):
                try:
                    links, unresolved = unpack_image(target, rootfs)
                    break
                except (tarfile.TarError, LookupFailed):
                    shutil.rmtree(rootfs, ignore_errors=True)
                    os.makedirs(rootfs)
                    if attempt == 2:
                        raise
            return {"rootfs": rootfs, "temporary": True, "links": links, "config": image_config(target),
                    "pinned": target, "platform_digest": platform_digest, "unresolved_hard_links": unresolved}
        except Exception:
            shutil.rmtree(rootfs, ignore_errors=True)
            raise
    if kind == "release":
        rootfs = tempfile.mkdtemp(prefix="release_", dir=cache_path("work", "x").rsplit("/", 1)[0])
        try:
            return {"rootfs": rootfs, "temporary": True, "links": {}, "config": {}, "pinned": target,
                    "artifact_digest": fetch_release(target, rootfs)}
        except Exception:
            shutil.rmtree(rootfs, ignore_errors=True)
            raise
    if kind == "maven":
        rootfs = cache_path("maven_targets", project, "x").rsplit("/", 1)[0]
        return {"rootfs": rootfs, "temporary": False, "links": {}, "config": {}, "pinned": target,
                "artifact_digest": fetch_maven(target, rootfs)}
    raise ValueError(f"unknown target kind {kind}")
