# Readers that take the build specification of one exact release of a JNI wrapper (release tag, submodule
# commit, POM, or a file in the published jar) and return the C libraries and versions it compiles in.
# A reader returns None when the specification is not readable and [] when it names no library.
import re
from .util import http_text, git_repo, git, git_tag, release_tag, tag_forms, is_release_version, LookupFailed

CENTRAL = "https://repo1.maven.org/maven2"
GH = "https://github.com"
RELEASE_TAG = re.compile(r"v?(\d+\.\d+\.\d+)")


def lib(name, version, evidence):
    return {"library": name, "version": version, "evidence": evidence}


def exact_tag(repo_dir, version, names=()):
    for f in tag_forms(version, names):
        if git_tag(repo_dir, f):
            return f
    return None


def macro_version(text, prefix):
    parts = [re.search(rf"#define {prefix}_{k}\s+(\d+)", text or "") for k in ("MAJOR", "MINOR", "RELEASE")]
    return ".".join(m.group(1) for m in parts) if all(parts) else None


def submodule_release(repo_dir, tag, path, upstream):
    t = git(repo_dir, "ls-tree", tag, path)
    if not t or t.split()[1] != "commit":
        return None, None, []
    commit = t.split()[2]
    up = git_repo(upstream)
    if git(up, "cat-file", "-e", commit + "^{commit}") is None:
        git(up, "fetch", "-q", "--tags", "--filter=blob:none", "origin", "+refs/tags/*:refs/tags/*")
    tags = (git(up, "tag", "--points-at", commit) or "").split()
    rel = sorted(RELEASE_TAG.fullmatch(t).group(1) for t in tags if RELEASE_TAG.fullmatch(t))
    return commit, (rel[0] if len(rel) == 1 else None), tags


def zstd_jni(v, jar):
    tag = release_tag(f"{GH}/luben/zstd-jni", v)
    if not tag:
        return None
    h = http_text(f"https://raw.githubusercontent.com/luben/zstd-jni/{tag}/src/main/native/zstd.h")
    ver = macro_version(h, "ZSTD_VERSION")
    return [lib("zstd", ver, f"luben/zstd-jni@{tag}:src/main/native/zstd.h")] if ver else None


def lz4_java(repo):
    def reader(v, jar):
        d = git_repo(f"{GH}/{repo}")
        tag = exact_tag(d, v, ("lz4-java",))
        if not tag:
            return None
        sub = submodule_release(d, tag, "src/lz4", f"{GH}/lz4/lz4")
        if sub[0]:
            commit, ver, tags = sub
            return [lib("lz4", ver, f"{repo}@{tag}: submodule src/lz4 = {commit[:10]} (tags: {' '.join(tags) or 'none'})")]
        ver = macro_version(git(d, "show", f"{tag}:src/lz4/lz4.h"), "LZ4_VERSION")
        return [lib("lz4", ver, f"{repo}@{tag}:src/lz4/lz4.h")] if ver else None
    return reader


def snappy_java(v, jar):
    from .maven_artifact import jar_entry
    m = re.search(r"SNAPPY_VERSION=(\S+)", jar_entry(jar, "org/xerial/snappy/VERSION").get("text") or "")
    return [lib("snappy", m.group(1), f"snappy-java-{v}.jar!/org/xerial/snappy/VERSION")] if m else None


def libffi(repo, path, names):
    def reader(v, jar):
        d = git_repo(f"{GH}/{repo}")
        tag = exact_tag(d, v, names)
        m = tag and re.search(r"AC_INIT\(\[libffi\],\s*\[([^\]]+)\]", git(d, "show", f"{tag}:{path}") or "")
        if not m:
            return None
        ver = m.group(1) if is_release_version(m.group(1)) else None
        return [lib("libffi", ver, f"{repo}@{tag}:{path} AC_INIT version {m.group(1)}")]
    return reader


def rocksdbjni(v, jar):
    base = ".".join(v.split(".")[:3])
    mk = http_text(f"https://raw.githubusercontent.com/facebook/rocksdb/v{base}/Makefile")
    if not mk:
        return None
    out = []
    for var, name in (("ZLIB_VER", "zlib"), ("BZIP2_VER", "bzip2"), ("SNAPPY_VER", "snappy"), ("LZ4_VER", "lz4"), ("ZSTD_VER", "zstd")):
        m = re.search(rf"^{var}\s*(\??):?=\s*(\S+)", mk, re.M)
        if m:
            pinned = not m.group(1)
            out.append(lib(name, m.group(2) if pinned else None,
                           f"rocksdb@v{base}/Makefile {var} {'=' if pinned else '?= (default, can be overridden)'} {m.group(2)}"))
    return out


def tcnative(v, jar):
    pom = http_text(f"{CENTRAL}/io/netty/netty-tcnative-parent/{v}/netty-tcnative-parent-{v}.pom")
    if pom is None:
        return None
    m = re.search(r"<boringsslCommitSha>(\w+)<", pom)
    return [lib("boringssl", None, f"netty-tcnative-parent-{v}.pom boringsslCommitSha={m.group(1)[:10] if m else 'absent'} (BoringSSL has no releases)")]


def aws_crt(v, jar):
    d = git_repo(f"{GH}/awslabs/aws-crt-java")
    tag = exact_tag(d, v)
    if not tag:
        return None
    commit, ver, tags = submodule_release(d, tag, "crt/aws-lc", f"{GH}/aws/aws-lc")
    if not commit:
        return []
    return [lib("aws-lc", ver, f"aws-crt-java@{tag}: submodule crt/aws-lc = {commit[:10]} (tags: {' '.join(tags) or 'none'})")]


READERS = {
    "com.github.luben:zstd-jni": zstd_jni,
    "org.lz4:lz4-java": lz4_java("lz4/lz4-java"),
    "at.yawk.lz4:lz4-java": lz4_java("yawkat/lz4-java"),
    "org.xerial.snappy:snappy-java": snappy_java,
    "net.java.dev.jna:jna": libffi("java-native-access/jna", "native/libffi/configure.ac", ()),
    "net.java.dev.jna:jna-jpms": libffi("java-native-access/jna", "native/libffi/configure.ac", ()),
    "com.github.jnr:jffi": libffi("jnr/jffi", "jni/libffi/configure.ac", ("jffi",)),
    "org.rocksdb:rocksdbjni": rocksdbjni,
    "io.netty:netty-tcnative-boringssl-static": tcnative,
    "software.amazon.awssdk.crt:aws-crt": aws_crt,
}


def read(gav, jar_url):
    g, a, v = gav.split(":")
    reader = READERS.get(f"{g}:{a}")
    return reader(v, jar_url) if reader else None
