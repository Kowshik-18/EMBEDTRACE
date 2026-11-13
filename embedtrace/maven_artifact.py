# Finds the published Maven Central artifact whose jar holds a byte-identical native file, and walks back
# to the earliest release with those bytes. Jar entries are read with HTTP range requests.
import io, os, re, time, zipfile, hashlib, urllib.parse, urllib.request, urllib.error, http.client
from .util import (http_json, http_cached, cache_path, key, read_json, write_json, elf_info, maven_version_key,
                   LookupFailed, UA)

CENTRAL = "https://repo1.maven.org/maven2"
SEARCH = "https://search.maven.org/solrsearch/select"
MAX_CANDIDATES = 40
MAX_VERSIONS = 300


class RemoteFile(io.RawIOBase):
    def __init__(self, url):
        r = urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers=UA), timeout=60)
        size = r.headers.get("Content-Length")
        if size is None:
            raise LookupFailed(f"no Content-Length for {url}")
        self.url, self.pos, self.size, self.blocks = url, 0, int(size), {}

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else (self.pos + off if whence == 1 else self.size + off)
        return self.pos

    def fetch(self, start, end):
        for attempt in range(6):
            try:
                rq = urllib.request.Request(self.url, headers=dict(UA, Range=f"bytes={start}-{end - 1}"))
                data = urllib.request.urlopen(rq, timeout=300).read()
                if len(data) == end - start:
                    return data
            except urllib.error.HTTPError as e:
                if e.code not in (403, 408, 429) and e.code < 500:
                    raise
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(min(60, 3 * 2 ** attempt))
        raise LookupFailed(f"range read failed {self.url}")

    def read(self, n=-1):
        n = self.size - self.pos if n is None or n < 0 else min(n, self.size - self.pos)
        B = 1 << 18
        if n > B:
            data = self.fetch(self.pos, self.pos + n)
            self.pos += n
            return data
        out = bytearray()
        while len(out) < n:
            start = (self.pos // B) * B
            if start not in self.blocks:
                self.blocks[start] = self.fetch(start, min(start + B, self.size))
            blk = self.blocks[start][self.pos - start: self.pos - start + n - len(out)]
            if not blk:
                raise LookupFailed(f"short range read from {self.url}")
            out += blk
            self.pos += len(blk)
        return bytes(out)


def jar_entry(url, name):
    p = cache_path("jar_entries", key(url + "!" + name) + ".json")
    c = read_json(p)
    if c is not None:
        return c
    last = None
    for attempt in range(4):
        try:
            z = zipfile.ZipFile(RemoteFile(url))
            data = z.read(name) if name in z.namelist() else None
            res = {"exists": True, "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                   "text": data.decode(errors="ignore") if data is not None and len(data) < 65536 and not data.startswith(b"\x7fELF") else None}
            break
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                res = {"exists": False, "sha256": None, "text": None}
                break
            last = e
            attempt < 3 and time.sleep(5 * 4 ** attempt)
            continue
        except (OSError, zipfile.BadZipFile, http.client.HTTPException, LookupFailed) as e:
            last = e
        attempt < 3 and time.sleep(5 * 4 ** attempt)
    else:
        raise LookupFailed(f"cannot read {name} from {url}: {type(last).__name__}")
    write_json(p, res)
    return res


def entry_sha256(url, name):
    return jar_entry(url, name)["sha256"]


def search(q, rows=20, core=None):
    params = {"q": q, "rows": rows, "wt": "json"}
    if core:
        params["core"] = core
    return http_json(f"{SEARCH}?{urllib.parse.urlencode(params)}", keep_empty=lambda d: d.get("response", {}).get("numFound", 0) > 0)


def by_jar_sha1(sha1):
    return [f"{d['g']}:{d['a']}:{d['v']}" for d in search(f'1:"{sha1}"')["response"]["docs"]]


def classifier_hint(gav, archive_path):
    _, a, v = gav.split(":")
    m = re.match(rf"{re.escape(a)}-{re.escape(v)}(-[\w.-]+)?\.jar$", os.path.basename(archive_path))
    return m.group(1) if m and m.group(1) else None


def classifiers(gav):
    g, a, v = gav.split(":")
    page = http_cached(f"{CENTRAL}/{g.replace('.', '/')}/{a}/{v}/", "listings") or ""
    found = re.findall(rf'href="{re.escape(a)}-{re.escape(v)}(-[\w.\-]+)\.jar"', page)
    return [c for c in found if c not in ("-sources", "-javadoc", "-tests", "-test-sources")]


def jar_urls(gav, hint=None, all_classifiers=True):
    g, a, v = gav.split(":")
    base = f"{CENTRAL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}"
    yield base + ".jar"
    seen = set()
    for c in ([hint] if hint else []) + (classifiers(gav) if all_classifiers else []):
        if c not in seen:
            seen.add(c)
            yield base + c + ".jar"


def versions(ga):
    g, a = ga.split(":")[:2]
    x = http_cached(f"{CENTRAL}/{g.replace('.', '/')}/{a}/maven-metadata.xml", "metadata")
    if x is None:
        raise LookupFailed(f"no maven-metadata.xml for {g}:{a}")
    return sorted(set(re.findall(r"<version>([^<]+)</version>", x)), key=maven_version_key)


def jni_classes(path):
    with open(path, "rb") as f:
        defined = elf_info(f.read())["defined"]
    count = {}
    for sym in defined:
        if not sym.startswith("Java_"):
            continue
        body = sym[5:].split("__")[0]
        parts, cur, i = [], "", 0
        while i < len(body):
            if body[i] == "_" and i + 1 < len(body) and body[i + 1] == "1":
                cur += "_"; i += 2
            elif body[i] == "_" and i + 1 < len(body) and body[i + 1] in "0123":
                cur += "?"; i += 2
            elif body[i] == "_":
                parts.append(cur); cur = ""; i += 1
            else:
                cur += body[i]; i += 1
        parts.append(cur)
        if len(parts) > 2:
            cls = ".".join(parts[:-1])
            count[cls] = count.get(cls, 0) + 1
    return sorted(count, key=lambda c: (-count[c], c))[:3]


def artifacts_with_class(cls):
    return sorted({f"{d['g']}:{d['a']}" for d in search(f'fc:"{cls}"', rows=50)["response"]["docs"]})


def scan_versions(ga, native):
    hint = classifier_hint(f"{ga}:x", native["archives"][-1]["path"])
    try:
        vs = list(reversed(versions(ga)))[:MAX_VERSIONS]
    except LookupFailed:
        return None
    names = " ".join(os.path.basename(l["path"]) for l in native["archives"])
    vs = sorted(vs, key=lambda v: f"-{v}." not in names and f"-{v}-" not in names)
    for v in vs:
        gav = f"{ga}:{v}"
        for url in jar_urls(gav, classifier_hint(gav, native["archives"][-1]["path"]) or hint, all_classifiers=False):
            if entry_sha256(url, native["entry"]) == native["sha256"]:
                return gav, url
    return None


def first_release(gav, url, entry, sha):
    g, a, v = gav.split(":")
    vs = versions(gav)
    if v not in vs:
        return gav, url, f"{v} not in maven-metadata.xml"
    older = [x for x in vs[:vs.index(v)] if maven_version_key(x) < maven_version_key(v)]
    first = (gav, url)
    for o in reversed(older):
        u = url.replace(f"/{v}/{a}-{v}", f"/{o}/{a}-{o}")
        if entry_sha256(u, entry) != sha:
            break
        first = (f"{g}:{a}:{o}", u)
    return first[0], first[1], "earliest release with these bytes"


def tokens(s):
    return {t for t in re.split(r"[/_.:\-]+", s.lower()) if len(t) > 2 and t not in ("lib", "jar", "native", "linux", "x86", "amd64", "org", "com", "net", "io")}


def published_matches(native, readers):
    level = native["archives"][-1]
    want = tokens(native["entry"])
    by_name = sorted(level["pom_gavs"], key=lambda g: (-len(tokens(g) & want), g))
    candidates = list(dict.fromkeys([(g, "jar SHA-1 search") for g in by_jar_sha1(level["sha1"])]))
    seen = {c[0] for c in candidates}
    for g in by_name[:MAX_CANDIDATES]:
        if g not in seen:
            candidates.append((g, "pom.properties in jar"))
            seen.add(g)
    found = []
    for gav, how in candidates:
        for url in jar_urls(gav, classifier_hint(gav, level["path"])):
            if entry_sha256(url, native["entry"]) == native["sha256"]:
                found.append((gav, url, how))
                break
    classes = []
    if not any(g.rsplit(":", 1)[0] in readers for g, _, _ in found):
        classes = jni_classes(native["store"])
        for cls in classes[:1]:
            pkg = cls.rsplit(".", 1)[0]
            jar_names = " ".join(os.path.basename(l["path"]).lower() for l in native["archives"])
            rank = lambda ga: (ga.split(":")[1].lower() + "-" not in jar_names, not pkg.startswith(ga.split(":")[0]), ga)
            owners = [ga for ga in sorted(artifacts_with_class(cls), key=rank) if rank(ga)[:2] != (True, True)]
            for ga in owners[:3]:
                hit = scan_versions(ga, native)
                if hit and hit[0] not in [f[0] for f in found]:
                    found.append((hit[0], hit[1], f"JNI symbols name class {cls}"))
                    break
    skipped = max(0, len(level["pom_gavs"]) - MAX_CANDIDATES)
    note = f"{len(candidates)} candidates checked" + (f", {skipped} lower-ranked not checked" if skipped else "")
    note += f"; JNI class {classes[0]}: newest {MAX_VERSIONS} releases of up to 3 owning artifacts checked" if classes else ""
    return found, note
