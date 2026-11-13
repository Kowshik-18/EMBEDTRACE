# Verifies C libraries compiled into a native file inside a Java archive: the same bytes must sit in a
# published Maven Central jar, and the build specification of the earliest such release must pin the library
# version. Wrappers without a reader fall back to an inspection of the release source tree.
from . import maven_artifact, build_specs, source_check


def find(native):
    base = {"carrier": "Java archive", "file": " > ".join(native["chain"]), "file_sha256": native["sha256"],
            "library": "", "version": "", "status": "", "identity_source": "", "build_spec_source": "",
            "symbol_evidence": "", "version_source": ""}
    found, note = maven_artifact.published_matches(native, build_specs.READERS)
    if not found:
        return [dict(base, identity_source=note, status="unresolved: no published artifact with this file")]
    jar_names = " ".join(l["path"].rsplit("/", 1)[-1] for l in native["archives"])
    with_reader = [f for f in found if f[0].rsplit(":", 1)[0] in build_specs.READERS]
    pool = sorted(with_reader or found, key=lambda f: (f[0].split(":")[1] + "-" not in jar_names, f[0]))
    gav, url, how = pool[0]
    gav, url, walk = maven_artifact.first_release(gav, url, native["entry"], native["sha256"])
    also = sorted({f[0] for f in found if f[0].rsplit(":", 1)[0] != gav.rsplit(":", 1)[0]})
    base["identity_source"] = f"{gav} ({how}; {walk}; same SHA-256 in {url})" + (f"; also inside {', '.join(also[:3])}" if also else "")

    ga = gav.rsplit(":", 1)[0]
    if ga in build_specs.READERS:
        libs = build_specs.read(gav, url)
        if libs is None:
            return [dict(base, status="unresolved: build specification not readable")]
        if not libs:
            return [dict(base, status="unresolved: build specification names no library")]
        return [dict(base, library=l["library"], version=l["version"] or "", build_spec_source=l["evidence"],
                     version_source=l["evidence"] if l["version"] else "",
                     status="verified" if l["version"] else "unresolved: version not pinned in build specification")
                for l in libs]

    src = source_check.check(gav)
    where = f"{src.get('repo', '')}@{src.get('tag', '')}"
    if src["result"] == "no third-party code":
        return [dict(base, build_spec_source=where, status="no embedded library (release source has only project code)")]
    if src["result"] == "third-party code present":
        files = ", ".join(list(src["third_party_files"])[:3])
        return [dict(base, build_spec_source=f"{where}: {files}", status="unresolved: third-party code present, library not named")]
    if src["result"] == "build fetches or links external code":
        return [dict(base, build_spec_source=f"{where}: {', '.join(src['external_build_files'][:3])}", status="unresolved: build fetches or links external code")]
    return [dict(base, build_spec_source=where, status=f"unresolved: {src['result']}")]
