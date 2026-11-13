# For a wrapper without a build-specification reader, inspects the C/C++ sources of the exact release:
# POM <scm> repository, exact release tag, module sources, and copyright holders. Files whose holders differ
# from those of the JNI files are third-party code. Submodules, build-time downloads or static links stay unresolved.
import os, re, glob, shutil
from .util import http_cached, sh, cache_path, key, release_tag, LookupFailed

CENTRAL = "https://repo1.maven.org/maven2"
SOURCE = r"\.(c|h|cc|cpp|cxx|hpp)$"
BUILD = r"(CMakeLists\.txt|Makefile|\.mk|\.cmake|build\.gradle|pom\.xml|configure\.ac|\.sh)$"
EXTERNAL = re.compile(r"FetchContent_Declare|ExternalProject_Add|\b(curl|wget)\s+\S*https?://|-l:lib\w+\.a\b|\blib\w+\.a\b", re.I)


def pom(g, a, v):
    return http_cached(f"{CENTRAL}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom", "poms") or ""


def scm_repo(g, a, v, depth=0):
    p = pom(g, a, v)
    m = re.search(r"<scm>(.*?)</scm>", p, re.S)
    if m:
        for u in re.findall(r"<(?:url|connection|developerConnection)>(.*?)</", m.group(1)):
            u = u.replace("scm:git:", "").replace("git@github.com:", "https://github.com/")
            gh = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/|$|\.git)", u)
            if gh and "${" not in u:
                return f"https://github.com/{gh.group(1)}/{gh.group(2)}"
            asf = re.search(r"gitbox\.apache\.org/repos/asf(?:\?p=|/)([\w.-]+?)\.git", u)
            if asf:
                return f"https://github.com/apache/{asf.group(1)}"
    parent = re.search(r"<parent>(.*?)</parent>", p, re.S)
    if parent and depth < 4:
        f = {k: re.search(rf"<{k}>(.*?)</{k}>", parent.group(1)) for k in ("groupId", "artifactId", "version")}
        if all(f.values()):
            return scm_repo(f["groupId"].group(1), f["artifactId"].group(1), f["version"].group(1), depth + 1)
    return None


def parent_ids(g, a, v, depth=0):
    parent = re.search(r"<parent>(.*?)</parent>", pom(g, a, v), re.S)
    if not parent or depth >= 4:
        return []
    f = {k: re.search(rf"<{k}>(.*?)</{k}>", parent.group(1)) for k in ("groupId", "artifactId", "version")}
    if not all(f.values()):
        return []
    pa = f["artifactId"].group(1)
    return [pa] + parent_ids(f["groupId"].group(1), pa, f["version"].group(1), depth + 1)


def checkout(repo, tag):
    d = cache_path("src_trees", re.sub(r"\W", "_", repo.split("github.com/")[1]) + "_" + key(repo + "@" + tag))
    if not os.path.isdir(d):
        tmp = d + ".partial"
        shutil.rmtree(tmp, ignore_errors=True)
        r = sh("git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", "--branch", tag, repo + ".git", tmp)
        if r.returncode or sh("git", "sparse-checkout", "set", "--no-cone", "*.c", "*.h", "*.cc", "*.cpp", "*.cxx", "*.hpp",
                              "pom.xml", ".gitmodules", "CMakeLists.txt", "*.cmake", "Makefile", "*.mk", "build.gradle",
                              "configure.ac", "*.sh", cwd=tmp).returncode:
            shutil.rmtree(tmp, ignore_errors=True)
            raise LookupFailed(f"checkout {repo}@{tag} failed")
        os.replace(tmp, d)
    return d


def artifact_id(pom_text):
    t = re.sub(r"<parent>.*?</parent>", "", pom_text, flags=re.S)
    t = re.sub(r"<(dependencies|dependencyManagement|build|profiles|plugins)>.*", "", t, flags=re.S)
    m = re.search(r"<artifactId>(.*?)</artifactId>", t)
    return m.group(1) if m else None


def holders(path):
    head = open(path, errors="ignore").read().splitlines()[:80]
    found = {m.group(1).strip().lower() for m in re.finditer(r"Licensed to (?:the )?([A-Z][\w ]+?)\s*\(", " ".join(head))}
    for line in head:
        m = re.search(r"(?:SPDX-FileCopyrightText:|copyright)\s*(?:\(c\)|©)?\s*(?:[\d\s,\-–]+)?\s*(?:by\s+)?(.+)", line, re.I)
        if m:
            h = re.sub(r"(?i)all rights reserved\.?|\(c\)|©|\d{4}(\s*[-–,]\s*\d{4})*|[*/#<>]|\bthe\b", " ", m.group(1))
            h = re.sub(r"\s+", " ", h).strip()
            h = re.sub(r"[\s.,;:]+$", "", h).replace(",", "").lower()
            if len(h) > 2 and not h.startswith(("notice", "holder", "owner", "law", "and license", "text")):
                found.add(h)
    return found


def check(gav):
    g, a, v = gav.split(":")
    repo = scm_repo(g, a, v)
    if not repo:
        return {"result": "repository not found"}
    tag = release_tag(repo, v, (a, repo.rsplit("/", 1)[1]) + tuple(parent_ids(g, a, v)))
    if not tag:
        return {"result": "release tag not found", "repo": repo}
    d = checkout(repo, tag)
    if os.path.exists(os.path.join(d, ".gitmodules")):
        return {"result": "release source has git submodules", "repo": repo, "tag": tag}
    modules = {artifact_id(open(p, errors="ignore").read()): os.path.dirname(p) for p in glob.glob(d + "/**/pom.xml", recursive=True)}
    if a not in modules:
        return {"result": "native source not found", "repo": repo, "tag": tag}
    mod_pom = open(os.path.join(modules[a], "pom.xml"), errors="ignore").read()
    dirs = {modules[a]} | {modules[x] for x in re.findall(r"<artifactItem>.*?<artifactId>(.*?)</artifactId>", mod_pom, re.S) if x in modules}
    tree = sorted({f for x in dirs for f in glob.glob(x + "/**/*", recursive=True) if os.path.isfile(f)})
    files = [f for f in tree if re.search(SOURCE, f)]
    if not files:
        return {"result": "native source not found", "repo": repo, "tag": tag}
    external = [os.path.relpath(f, d) for f in tree if re.search(BUILD, f) and EXTERNAL.search(open(f, errors="ignore").read())]
    per_file = {os.path.relpath(f, d): holders(f) for f in files}
    jni = [f for f in files if f.endswith((".c", ".cc", ".cpp", ".cxx"))
           and re.search(r"\bJNI_OnLoad\s*\(|\bJava_\w+\s*\(", open(f, errors="ignore").read())]
    project = set().union(*[per_file[os.path.relpath(f, d)] for f in jni]) if jni else set()
    third = {f: sorted(h - project) for f, h in per_file.items() if h and not h <= project}
    if third:
        result = "third-party code present"
    elif external:
        result = "build fetches or links external code"
    elif project:
        result = "no third-party code"
    else:
        result = "no copyright notices on JNI files"
    return {"result": result, "repo": repo, "tag": tag, "project_holders": sorted(project),
            "third_party_files": third, "external_build_files": external[:5]}
