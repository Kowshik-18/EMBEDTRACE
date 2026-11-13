# Verifies C libraries compiled into the native files of a Java runtime. OpenJDK's legal files at the runtime's
# source commit name each bundled library and its version; a copy is verified when the file is byte-identical to the
# vendor's build, the build files compile the library's source folder into it, and it defines the library's functions.
import os, re, shutil, tarfile, tempfile
from .util import (sh, GIT_ENV, download, sha256, sha256_file, cache_path, key, write_json, read_json,
                   elf_info, LookupFailed)

VENDOR_HOSTS = re.compile(r"^https://(github\.com/(adoptium|AdoptOpenJDK|bell-sw)/|download\.bell-sw\.com/)")
LEGAL = re.compile(r"^src/[^/]+/(?:share|unix|linux)/legal/([^/]+)\.md$")
NATIVE = re.compile(r"^src/[^/]+/(?:share|unix|linux)/native/")
CODE = re.compile(r"\.(c|cc|cpp|cxx)$")
MAKE = re.compile(r"(^|/)make/.*\.gmk$")
VERSION = re.compile(r"(?<![\w.-])v?\s?(\d+(?:\.\d+)*[a-z]?)(?![\w.-])", re.I)
DEFINITION = re.compile(r"(?<![\w:~.>])([A-Za-z_]\w*)\s*\(((?:[^;{}()]|\((?:[^;{}()]|\([^;{}()]*\))*\))*)\)\s*(?:const\s*)?(?:noexcept\s*)?\{")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "else", "do", "case", "defined", "catch", "operator",
            "static_assert", "decltype", "alignof", "alignas", "typeof", "__attribute__", "__declspec", "throw", "new",
            "delete", "template", "typename", "struct", "union", "enum", "class", "namespace", "using", "extern"}
CHUNK = 500
PARSER = "parser-v3"


def norm(x):
    return re.sub(r"^lib", "", re.sub(r"[^a-z0-9]", "", x.lower()))


def major_of(R):
    v = R.get("JAVA_VERSION", "")
    m = re.match(r"1\.(\d+)", v)
    return m.group(1) if m else v.split(".")[0].split("+")[0].split("-")[0]


def legal_version(heading):
    found = VERSION.findall(heading)
    return found[-1] if found else None


def bellsoft_version(R):
    if major_of(R) == "8":
        m = re.search(r"1\.8\.0_(\d+)-b(\d+)", R.get("JAVA_RUNTIME_VERSION", "") + " " + R.get("FULL_VERSION", ""))
        return f"8u{m.group(1)}+{m.group(2)}" if m else None
    v = R.get("JAVA_RUNTIME_VERSION", "").replace("-LTS", "")
    return v or None


def is_bellsoft(R):
    return "BellSoft" in R.get("IMPLEMENTOR", "")


def full_sha(repo, abbrev):
    p = cache_path("github_commits", key(repo + abbrev) + ".json")
    c = read_json(p)
    if c:
        return c["sha"]
    d = cache_path("git_history", repo.replace("/", "_"))
    if not os.path.isdir(d):
        tmp = d + ".partial"
        shutil.rmtree(tmp, ignore_errors=True)
        r = sh("git", "clone", "-q", "--bare", "--filter=tree:0", f"https://github.com/{repo}.git", tmp, timeout=3600)
        if r.returncode:
            shutil.rmtree(tmp, ignore_errors=True)
            if "not found" in r.stderr.lower():
                return None
            raise LookupFailed(f"git clone {repo} failed")
        os.replace(tmp, d)
    r = sh("git", "-C", d, "rev-parse", "-q", "--verify", abbrev + "^{commit}")
    if r.returncode:
        f = sh("git", "-C", d, "fetch", "-q", "--filter=tree:0", "origin", "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*", timeout=3600)
        if f.returncode:
            raise LookupFailed(f"git fetch {repo} failed")
        r = sh("git", "-C", d, "rev-parse", "-q", "--verify", abbrev + "^{commit}")
    if r.returncode:
        return None
    sha = r.stdout.strip()
    write_json(p, {"sha": sha})
    return sha


def source_ref(R):
    if is_bellsoft(R):
        v = bellsoft_version(R)
        if not v:
            return None, "BellSoft version not in release file"
        return ("tar", f"https://github.com/bell-sw/Liberica/releases/download/{v.replace('+', '%2B')}/bellsoft-jdk{v}-src.tar.gz")
    m = re.search(r"git:([0-9a-f]{7,40})(\+?)", R.get("SOURCE", ""))
    if not m:
        return None, "no source commit in release file"
    if m.group(2):
        return None, "source commit has local changes (+)"
    repo = R.get("SOURCE_REPO", "").replace(".git", "").replace("https://github.com/", "").strip("/")
    repos = [repo] if repo else [f"adoptium/jdk{major_of(R)}u", f"openjdk/jdk{major_of(R)}u"]
    for r in repos:
        sha = full_sha(r, m.group(1))
        if sha:
            return "git", f"{r}@{sha}"
    return None, f"commit {m.group(1)} not found in {', '.join(repos)}"


def git_checkout(repo, sha):
    d = cache_path("jdk_src", repo.replace("/", "_") + "_" + sha[:16])
    if not os.path.isdir(d):
        tmp = d + ".partial"
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp)
        sh("git", "init", "-q", cwd=tmp)
        r = sh("git", "fetch", "-q", "--depth", "1", "--filter=blob:none", f"https://github.com/{repo}.git", sha, cwd=tmp)
        if r.returncode:
            shutil.rmtree(tmp, ignore_errors=True)
            raise LookupFailed(f"git fetch {repo}@{sha[:12]} failed")
        os.replace(tmp, d)
    return d


class Source:
    def __init__(self, R):
        self.kind, self.ref = source_ref(R)
        self.text = {}
        if self.kind == "git":
            self.repo, self.sha = self.ref.split("@")
            self.dir = git_checkout(self.repo, self.sha)
            r = sh("git", "ls-tree", "-r", self.sha, cwd=self.dir)
            if r.returncode:
                raise LookupFailed(f"git ls-tree {self.ref} failed")
            self.oid = {}
            for line in r.stdout.splitlines():
                meta, path = line.split("\t", 1)
                if meta.split()[1] == "blob":
                    self.oid[path] = meta.split()[2]
            self.names = set(self.oid)
        elif self.kind == "tar":
            self.tar = tar_members(self.ref)
            if self.tar is None:
                self.kind, self.ref = None, "Liberica source archive not found"
            else:
                self.names = set(self.tar)

    def load(self, paths):
        paths = [p for p in dict.fromkeys(paths) if p in self.names and p not in self.text]
        if not paths:
            return
        if self.kind == "tar":
            self.text.update({p: self.tar[p] for p in paths})
            return
        oids = sorted({self.oid[p] for p in paths})
        missing = sorted(set(oids) - present_objects(self.dir, self.sha, paths))
        for i in range(0, len(missing), CHUNK):
            r = sh_input(["git", "-c", "gc.auto=0", "-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "--no-tags",
                          "--no-write-fetch-head", "--filter=blob:none", "--stdin", f"https://github.com/{self.repo}.git"],
                         "\n".join(missing[i:i + CHUNK]) + "\n", self.dir, raw=True)
            if r.returncode:
                raise LookupFailed(f"git fetch of {len(missing)} files from {self.repo} failed")
        blobs = read_blobs(oids, self.dir)
        for p in paths:
            if self.oid[p] not in blobs:
                raise LookupFailed(f"blob for {p} missing after fetch")
            self.text[p] = blobs[self.oid[p]]

    def read(self, path):
        self.load([path])
        return self.text.get(path)

    def build_files(self):
        paths = sorted(n for n in self.names if MAKE.search(n) and re.search(r"(Lib|Libraries|Launcher|Executable)", os.path.basename(n)))
        self.load(paths)
        return {p: self.text[p] for p in paths}


def present_objects(cwd, sha, paths):
    present = set()
    for i in range(0, len(paths), CHUNK):
        r = sh("git", "rev-list", "--objects", "--missing=print", "--no-object-names", sha, "--", *paths[i:i + CHUNK], cwd=cwd)
        if r.returncode:
            raise LookupFailed("git rev-list failed")
        present |= {l for l in r.stdout.split() if not l.startswith("?")}
    return present


def sh_input(cmd, data, cwd, raw=False):
    import subprocess
    try:
        r = subprocess.run(cmd, input=data, cwd=cwd, capture_output=True, text=True, timeout=900, env=GIT_ENV)
    except subprocess.TimeoutExpired:
        raise LookupFailed(f"timeout: {' '.join(cmd[:3])}")
    return r if raw else r.stdout


def read_blobs(oids, cwd):
    import subprocess
    try:
        r = subprocess.run(["git", "cat-file", "--batch"], input=("\n".join(oids) + "\n").encode(),
                           cwd=cwd, capture_output=True, timeout=900, env=GIT_ENV)
    except subprocess.TimeoutExpired:
        raise LookupFailed("timeout: git cat-file")
    out, data, i = {}, r.stdout, 0
    while i < len(data):
        nl = data.find(b"\n", i)
        if nl < 0:
            raise LookupFailed("truncated git cat-file output")
        head = data[i:nl].decode().split()
        if len(head) < 3 or head[1] != "blob":
            i = nl + 1
            continue
        size = int(head[2])
        out[head[0]] = data[nl + 1: nl + 1 + size].decode(errors="ignore")
        i = nl + 1 + size + 1
    return out


def tar_members(url):
    p = cache_path("jdk_src", key(url + "#legal-native-make-" + PARSER) + ".json")
    c = read_json(p)
    if c is not None:
        return c
    tmpdir = tempfile.mkdtemp(dir=os.path.dirname(p))
    try:
        f = os.path.join(tmpdir, "src.tar.gz")
        if not download(url, f):
            return None
        got = {}
        with tarfile.open(f, "r:gz") as tf:
            for m in tf:
                n = m.name[2:] if m.name.startswith("./") else m.name
                n = n.split("/", 1)[1] if "/" in n else n
                if m.isfile() and (LEGAL.match(n) or MAKE.search(n) or (NATIVE.match(n) and CODE.search(n))):
                    got[n] = tf.extractfile(m).read().decode(errors="ignore")
        write_json(p, got)
        return got
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def bundled_libraries(src):
    dirs = set()
    for n in src.names:
        if NATIVE.match(n):
            parts = n.split("/")[:-1]
            dirs.update("/".join(parts[:i]) for i in range(5, len(parts) + 1))
    found = {}
    for p in sorted(src.names):
        m = LEGAL.match(p)
        if not m or len(norm(m.group(1))) < 3 or norm(m.group(1)) in found:
            continue
        stem = norm(m.group(1))
        match = [d for d in dirs if norm(os.path.basename(d)) == stem or norm(os.path.basename(d)).endswith(stem)]
        if not match:
            continue
        depth = min(d.count("/") for d in match)
        top = sorted(d for d in match if d.count("/") == depth)
        code = [n for n in src.names if CODE.search(n) and any(n.startswith(d + "/") for d in top)]
        if code:
            found[stem] = {"library": m.group(1), "legal": p, "dirs": top, "code": sorted(code)}
    src.load([l["legal"] for l in found.values()])
    for l in found.values():
        heading = next((x for x in src.text.get(l["legal"], "").splitlines() if x.startswith("## ")), "")
        l["heading"], l["version"] = heading[3:].strip(), legal_version(heading)
    return sorted(found.values(), key=lambda l: l["library"])


TOKENS = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\\n])*\'', re.S)


def first_branch(text):
    out, stack = [], []
    for line in text.split("\n"):
        d = re.match(r"\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)", line)
        if d:
            kind = d.group(1)
            if kind in ("if", "ifdef", "ifndef"):
                parent = all(stack)
                dead = kind == "if" and re.match(r"\s*0\s*$", d.group(2))
                stack.append(parent and not dead)
                stack.append(None)
                stack[-1] = "taken" if stack[-2] else "open"
            elif kind in ("elif", "else") and len(stack) >= 2:
                state = stack[-1]
                stack[-2] = all(stack[:-2]) and state == "open"
                stack[-1] = "taken" if stack[-2] or state == "taken" else "open"
            elif kind == "endif" and len(stack) >= 2:
                del stack[-2:]
            out.append("")
        elif all(stack[0::2]) if stack else True:
            out.append(line)
        else:
            out.append("")
    return "\n".join(out)


def strip_code(text):
    text = TOKENS.sub(lambda m: '""' if m.group(0)[0] == '"' else ("''" if m.group(0)[0] == "'" else " "), text)
    text = re.sub(r"\\\n", " ", text)
    text = first_branch(text)
    return re.sub(r"^\s*#[^\n]*", " ", text, flags=re.M)


TRANSPARENT = re.compile(r'(?:extern\s*""|namespace(?:\s+[\w:]+)?)\s*$')


def defined_functions(text):
    names, code = set(), strip_code(text)
    if re.search(r"^\s*#\s*include\s*[<\"]jni\.h", text, re.M) or re.search(r"\bJNIEXPORT\b|\bJava_\w+\s*\(", code):
        return names
    marks = sorted([(m.start(), "def", m) for m in DEFINITION.finditer(code)] +
                   [(m.start(), m.group(0), None) for m in re.finditer(r"[{}]", code)], key=lambda x: (x[0], x[1] != "def"))
    stack = []
    for pos, kind, m in marks:
        if kind == "{":
            stack.append(bool(TRANSPARENT.search(code[max(0, pos - 80):pos])))
        elif kind == "}":
            if stack:
                stack.pop()
        else:
            name = m.group(1)
            if not all(stack) or name in KEYWORDS or name == "main" or name.upper() == name:
                continue
            start = max(code.rfind(";", 0, pos), code.rfind("}", 0, pos), code.rfind("{", 0, pos), 0)
            if re.search(r"\bstatic\b", code[start:pos]):
                continue
            names.add(name)
    return names


def library_functions(src, lib):
    p = cache_path("jdk_functions", key(PARSER + src.ref + "|" + "|".join(lib["dirs"])) + ".json")
    c = read_json(p)
    if c is not None:
        return set(c)
    src.load(lib["code"])
    names = set()
    for f in lib["code"]:
        names |= defined_functions(src.text[f])
    write_json(p, sorted(names))
    return names


BLOCK = re.compile(r"\$\(eval \$\(call (SetupJdkLibrary|SetupJdkExecutable|SetupNativeCompilation|SetupBuildLauncher)\s*,\s*(\w+)\s*,(.*?)\)\)\s*$", re.S | re.M)
EXCLUDE = re.compile(r"\b\w*EXCLUDE\w*\s*\+?:?=[^\n,]*")


def build_spec(files):
    spec = {}
    for text in files.values():
        text = re.sub(r"\\\n", " ", text or "")
        defs = {}
        for m in re.finditer(r"^\s*([A-Za-z0-9_]+)\s*\+?:?=\s*(.*)$", text, re.M):
            if "EXCLUDE" not in m.group(1):
                defs.setdefault(m.group(1), []).append(re.sub(r"#.*", "", m.group(2)))
        blocks = list(BLOCK.finditer(text))
        stems = {}
        for m in blocks:
            var = m.group(2)
            stems[var] = var
            stems[var.replace("BUILD_", "", 1)] = var
        owner = {}
        for k in defs:
            best = max((s for s in stems if k.startswith(s + "_")), key=len, default=None)
            if best:
                owner.setdefault(stems[best], []).append(k)

        def expand(t, depth=2):
            if depth == 0:
                return t
            refs = set(re.findall(r"\$\(([A-Za-z0-9_]+)\)", t))
            return t + " " + " ".join(expand(" ".join(defs.get(r, [])), depth - 1) for r in refs)

        for m in blocks:
            kind, var, body = m.groups()
            nm = re.search(r"\b(NAME|LIBRARY|PROGRAM)\s*:=\s*([A-Za-z0-9_]+)", body)
            if not nm:
                continue
            exe = kind in ("SetupJdkExecutable", "SetupBuildLauncher") or nm.group(1) == "PROGRAM"
            fname = nm.group(2) if exe else f"lib{nm.group(2)}.so"
            extra = " ".join(" ".join(defs[k]) for k in owner.get(var, []))
            body = EXCLUDE.sub(" ", re.sub(r"#.*", "", body))
            spec.setdefault(fname, {"name": nm.group(2), "text": ""})["text"] += " " + expand(body + " " + extra)
    return spec


def build_links(spec, fname, lib):
    entry = spec.get(fname)
    if not entry:
        return False
    for d in lib["dirs"]:
        if "lib" + entry["name"] in d.split("/") or entry["name"] in d.split("/"):
            return True
        base = os.path.basename(d)
        if re.search(rf"(?<![\w.-]){re.escape(base)}(?![\w.-])", entry["text"]):
            return True
    return False


def archive_urls(R, libc, image_config):
    urls = []
    for h in image_config.get("history", []):
        for u in re.findall(r"https?://[^\s\"';|]+\.tar\.gz", h.get("created_by", "")):
            if VENDOR_HOSTS.match(u) and re.search(r"(x64|x86_64|amd64)", u) and re.search(r"(jdk|jre)", u, re.I):
                urls.append(u)
    imp, iv, rv = R.get("IMPLEMENTOR", ""), R.get("IMPLEMENTOR_VERSION", ""), R.get("JAVA_RUNTIME_VERSION", "")
    osname = "alpine-linux" if libc == "musl" else "linux"
    if "Adoptium" in imp or "AdoptOpenJDK" in imp:
        v = re.sub(r"^(Temurin|AdoptOpenJDK)-", "", iv) or rv
        if major_of(R) == "8":
            m = re.search(r"1\.8\.0_(\d+)-b(\d+)", v) or re.search(r"8u(\d+)-?b(\d+)", v) or re.search(r"1\.8\.0_(\d+)-b(\d+)", R.get("FULL_VERSION", ""))
            if m:
                u, b = m.groups()
                for kind in ("jre", "jdk"):
                    urls.append(f"https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u{u}-b{b}/OpenJDK8U-{kind}_x64_{osname}_hotspot_8u{u}b{b}.tar.gz")
        elif v:
            v = v.replace("-LTS", "")
            maj, fv = v.split(".")[0].split("+")[0], v.replace("+", "_")
            tag = ("jdk-" + v).replace("+", "%2B")
            for kind in ("jre", "jdk"):
                urls.append(f"https://github.com/adoptium/temurin{maj}-binaries/releases/download/{tag}/OpenJDK{maj}U-{kind}_x64_{osname}_hotspot_{fv}.tar.gz")
                if "." in fv.split("_")[-1]:
                    urls.append(f"https://github.com/adoptium/temurin{maj}-binaries/releases/download/{tag}/OpenJDK{maj}U-{kind}_x64_{osname}_hotspot_{fv.rsplit('.', 1)[0]}.tar.gz")
    if is_bellsoft(R) and bellsoft_version(R):
        v = bellsoft_version(R)
        base = f"https://github.com/bell-sw/Liberica/releases/download/{v.replace('+', '%2B')}/bellsoft-"
        arches = ("x64-musl", "amd64-musl") if libc == "musl" else ("amd64",)
        for kind in ("jre", "jdk"):
            for arch in arches:
                for flavour in ("-lite", "", "-full"):
                    urls.append(f"{base}{kind}{v}-linux-{arch}{flavour}.tar.gz")
    return list(dict.fromkeys(urls))


def official_hashes(url):
    p = cache_path("official", key(url) + ".json")
    c = read_json(p)
    if c is not None:
        return c
    tmpdir = tempfile.mkdtemp(dir=os.path.dirname(p))
    try:
        f = os.path.join(tmpdir, "build.tar.gz")
        res = {"url": url, "ok": False, "files": {}}
        if download(url, f):
            res["ok"] = True
            with tarfile.open(f, "r:gz") as tf:
                for m in tf:
                    if m.isfile():
                        b = tf.extractfile(m).read()
                        if b[:4] == b"\x7fELF":
                            res["files"][m.name.split("/", 1)[-1]] = sha256(b)
        write_json(p, res)
        return res
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def same_as_official(official, rel, h):
    if official["files"].get(rel) == h:
        return True
    return "-jdk" in (official["url"] or "") and official["files"].get("jre/" + rel) == h


def base_row(runtime, rel, h):
    return {"carrier": "Java runtime", "file": runtime["home"].rstrip("/") + "/" + rel, "file_sha256": h,
            "library": "", "version": "", "status": "", "identity_source": "", "build_spec_source": "",
            "symbol_evidence": "", "version_source": ""}


def find(runtime, image_config):
    R = runtime["release"]
    hashes = {rel: sha256_file(p) for rel, p in runtime["elf"].items()}
    src = Source(R)
    if src.kind is None:
        return [dict(base_row(runtime, "release", ""), status=f"unresolved: runtime source not available ({src.ref})")]
    libs = bundled_libraries(src)
    if not libs:
        reason = "no legal files at source commit" if not any(LEGAL.match(n) for n in src.names) else "no bundled native library in legal files"
        return [dict(base_row(runtime, "release", ""), status=f"unresolved: {reason}", build_spec_source=src.ref)]

    best = None
    for url in archive_urls(R, runtime["libc"], image_config):
        o = official_hashes(url)
        if o["ok"]:
            n = sum(same_as_official(o, rel, h) for rel, h in hashes.items())
            if best is None or n > best[1]:
                best = (o, n)
    official = best[0] if best and best[1] else {"url": None, "files": {}}

    spec = build_spec(src.build_files())
    funcs = {l["library"]: library_functions(src, l) for l in libs}

    rows = []
    for rel, path in sorted(runtime["elf"].items()):
        with open(path, "rb") as f:
            data = f.read()
        try:
            info = elf_info(data)
        except Exception as e:
            rows.append(dict(base_row(runtime, rel, hashes[rel]), status=f"unresolved: ELF not parsable ({type(e).__name__})"))
            continue
        identical = same_as_official(official, rel, hashes[rel])
        for lib in libs:
            F = funcs[lib["library"]]
            defined, imported = F & info["defined"], F & info["imported"]
            linked = build_links(spec, os.path.basename(rel), lib)
            if not defined and not imported and not linked:
                continue
            row = dict(base_row(runtime, rel, hashes[rel]), library=lib["library"], version=lib["version"] or "",
                       identity_source=official["url"] or "", build_spec_source=src.ref,
                       symbol_evidence=f"defines {len(defined)}, imports {len(imported)} of {len(F)} functions defined in {', '.join(lib['dirs'])}",
                       version_source=f"{src.ref}:{lib['legal']} ({lib['heading']})")
            system = sorted(n for n in info["needed"] if norm(n.split(".so")[0]).startswith(norm(lib["library"])))
            if system:
                row["symbol_evidence"] += f"; needs {', '.join(system)}"
            if (imported or system) and not defined:
                rows.append(dict(row, status="no embedded library (links the library dynamically)"))
                continue
            checks = {"official build": identical, "build files": linked, "symbols": bool(defined) and not imported and not system,
                      "legal version": bool(lib["version"])}
            failed = [k for k, ok in checks.items() if not ok]
            rows.append(dict(row, status="verified" if not failed else "unresolved: no " + ", no ".join(failed)))
    return rows
