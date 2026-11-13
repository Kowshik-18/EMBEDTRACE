# Shared helpers: subprocess calls, HTTP with retry and on-disk cache, atomic writes,
# ELF checks and symbol tables, git access, and exact release-tag matching.
import os, re, io, json, time, shutil, hashlib, tempfile, subprocess, urllib.request, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.environ.get("EMBEDTRACE_CACHE", os.path.join(ROOT, "cache"))
CRANE = os.environ.get("CRANE", "crane")
PLATFORM = "linux/amd64"
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true")
UA = {"User-Agent": "EmbedTrace/1.0"}


class LookupFailed(Exception):
    pass


def sh(*args, cwd=None, timeout=900):
    try:
        return subprocess.run(list(args), cwd=cwd, capture_output=True, text=True, env=GIT_ENV, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def key(s):
    return hashlib.sha1(s.encode()).hexdigest()[:20]


def cache_path(*parts):
    p = os.path.join(CACHE, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def write_atomic(path, data, mode="w"):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".tmp_")
    with os.fdopen(fd, mode) as f:
        f.write(data)
    os.replace(tmp, path)


def write_json(path, obj):
    write_atomic(path, json.dumps(obj, indent=1))


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _open(url, timeout, headers=None):
    for attempt in range(6):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=dict(UA, **(headers or {}))), timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return None
            if e.code not in (403, 408, 429) and e.code < 500:
                raise LookupFailed(f"HTTP {e.code} {url}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            if isinstance(e, ValueError) and "unknown url" in str(e).lower():
                raise LookupFailed(f"bad URL {url}")
        time.sleep(min(60, 2 ** attempt * 2))
    raise LookupFailed(f"no response from {url}")


def http(url, timeout=120, headers=None):
    for attempt in range(3):
        r = _open(url, timeout, headers)
        if r is None:
            return None
        try:
            return r.read()
        except (OSError, Exception) as e:
            last = e
            time.sleep(2 ** attempt)
    raise LookupFailed(f"read failed {url}: {type(last).__name__}")


def http_text(url):
    b = http(url)
    return b.decode(errors="ignore") if b is not None else None


def http_cached(url, kind="http"):
    p = cache_path(kind, key(url) + ".json")
    c = read_json(p)
    if c is not None:
        return c["body"]
    b = http(url)
    body = b.decode(errors="ignore") if b is not None else None
    write_json(p, {"url": url, "body": body})
    return body


def http_json(url, keep_empty=lambda d: True):
    p = cache_path("search", key(url) + ".json")
    c = read_json(p)
    if c is not None:
        return c
    b = http(url)
    if b is None:
        raise LookupFailed(f"404 from search {url}")
    try:
        d = json.loads(b)
    except ValueError:
        raise LookupFailed(f"non-JSON reply {url}")
    if keep_empty(d):
        write_json(p, d)
    return d


def download(url, dest, timeout=900):
    r = _open(url, timeout)
    if r is None:
        return False
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(dest)), prefix=".dl_")
    try:
        with os.fdopen(fd, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
        os.replace(tmp, dest)
    except Exception as e:
        os.path.exists(tmp) and os.remove(tmp)
        raise LookupFailed(f"download failed {url}: {type(e).__name__}")
    return True


def is_elf(b):
    return b[:4] == b"\x7fELF"


def is_linux_x86_64_elf(b):
    return len(b) > 64 and is_elf(b) and b[4] == 2 and b[5] == 1 and b[7] in (0, 3) and b[18:20] == b"\x3e\x00"


def elf_info(data):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    defined, imported, needed, interp = set(), set(), set(), ""
    elf = ELFFile(io.BytesIO(data))
    for sec in elf.iter_sections():
        if sec.name in (".dynsym", ".symtab"):
            for s in sec.iter_symbols():
                if not s.name:
                    continue
                if s["st_shndx"] == "SHN_UNDEF":
                    imported.add(s.name)
                elif s["st_info"]["type"] == "STT_FUNC":
                    defined.add(s.name)
        elif isinstance(sec, DynamicSection):
            needed |= {t.needed for t in sec.iter_tags() if t.entry.d_tag == "DT_NEEDED"}
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_INTERP":
            interp = seg.get_interp_name()
    return {"defined": defined, "imported": imported - defined, "needed": needed, "interp": interp}


def git(repo_dir, *args):
    r = sh("git", "-C", repo_dir, *args)
    return r.stdout.strip() if r.returncode == 0 else None


def git_repo(url):
    d = cache_path("git", re.sub(r"\W", "_", url.split("github.com/")[-1]) + "_" + key(url))
    if not os.path.isdir(d):
        tmp = d + ".partial"
        shutil.rmtree(tmp, ignore_errors=True)
        r = sh("git", "clone", "-q", "--bare", "--filter=blob:none", url + ".git", tmp)
        if r.returncode:
            shutil.rmtree(tmp, ignore_errors=True)
            raise LookupFailed(f"git clone failed {url}")
        os.replace(tmp, d)
    return d


def git_tag(repo_dir, tag):
    ref = f"refs/tags/{tag}"
    if git(repo_dir, "rev-parse", "-q", "--verify", ref) is None:
        sh("git", "-C", repo_dir, "fetch", "-q", "--tags", "--filter=blob:none", "origin", "+refs/tags/*:refs/tags/*")
    return tag if git(repo_dir, "rev-parse", "-q", "--verify", ref) is not None else None


def remote_tags(url):
    r = sh("git", "ls-remote", "--tags", url + ".git")
    if r.returncode and re.search(r"could not read Username|Authentication failed|not found|does not exist", r.stderr, re.I):
        return set()
    if r.returncode:
        raise LookupFailed(f"git ls-remote failed {url}")
    return {l.split("refs/tags/")[1].replace("^{}", "") for l in r.stdout.splitlines() if "refs/tags/" in l}


def tag_forms(version, names=()):
    forms = [version, "v" + version, "rel/" + version, "release-" + version, "rel/v" + version]
    for n in names:
        forms += [f"{n}-{version}", f"rel/{n}-{version}", f"{n}-v{version}", f"{n}_{version}"]
    return list(dict.fromkeys(forms))


def release_tag(url, version, names=()):
    tags = remote_tags(url)
    for f in tag_forms(version, names):
        if f in tags:
            return f
    return None


VERSION_RX = re.compile(r"(\d+|[a-z]+)")
QUALIFIER = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3, "rc": -2, "cr": -2, "snapshot": -1, "": 0, "ga": 0, "final": 0, "release": 0, "sp": 1}


def maven_version_key(v):
    out = []
    for t in VERSION_RX.findall(v.lower()):
        out.append((1, int(t), "") if t.isdigit() else (0, QUALIFIER.get(t, 0.5), t))
    while out and out[-1] == (1, 0, ""):
        out.pop()
    return out


def is_release_version(v):
    return re.fullmatch(r"\d+(\.\d+)*", v or "") is not None
