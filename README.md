# EmbedTrace

EmbedTrace finds C libraries that a build compiled into the native files of Java runtimes and Java archives
(embedded copies), and verifies each copy and its version with build provenance.
This package runs it on the 50 Apache Java projects with the highest Criticality Score in
[ose-metadata](https://github.com/OpenRefactory-Inc/ose-metadata), and then compares the copies with SBOMs from three generators.

## Prerequisites

- Linux x86-64, Python 3.11.4 or later, `git`, about 40 GB of free disk, and Internet access
  (Docker Hub, Maven Central, `search.maven.org`, GitHub, `archive.apache.org`)
- `pip install -r requirements.txt`
- [crane](https://github.com/google/go-containerregistry/releases) 0.22 or later on `PATH`
- `rpm` on `PATH` (needed only for images with an RPM database)
- For the SBOM comparison only: [Syft](https://github.com/anchore/syft) 1.42.4,
  [Trivy](https://github.com/aquasecurity/trivy) 0.76.1, and [cdxgen](https://github.com/CycloneDX/cdxgen) 12.9.0 on `PATH`

## Dataset

`datasets/projects.csv` lists the 50 Apache Java projects with the highest Criticality Score in ose-metadata,
with each project's rank, score, and one pinned target:

- `image` (25 projects): the project's official Docker image. `tag` is the tag we resolved on 2026-11-12
  (`latest` unless the project publishes no `latest`), and `target` pins it by digest.
- `release` (15 projects): the project's official binary release on `archive.apache.org`.
- `maven` (10 projects without an image or a binary release): the jars of one release on Maven Central
  (`groupId[,groupId|groupId:artifactId]@version`).

`python datasets/check_projects.py` checks the list against ose-metadata.
`python datasets/pin_images.py` resolves each image tag again and reports whether it still points to the pinned digest.

## How each target is fetched

- `image`: `crane export --platform linux/amd64 <repo>@<digest>` writes the image's merged file system (all layers,
  with deleted files removed) to a temporary folder: the file system a container of this image starts from.
  No container is started and no Docker daemon is needed. Syft, Trivy, and cdxgen read the same folder.
- `release`: the archive is downloaded, checked against its published `.sha512` (or `.sha256`) file, and unpacked.
- `maven`: every jar of that version (without sources, javadoc, or test jars) is downloaded from Maven Central.

## Run

```
python detect.py                      # 1. find and verify embedded copies    -> results/copies/
python summarize.py                   # 2. print the copies per library       -> results/copies_by_library.csv
python sbom/generate_sboms.py         # 3. generate SBOMs (Syft, Trivy, cdxgen) -> results/sboms/ (gzip)
python sbom/compare.py                # 4. compare copies with the SBOMs      -> results/comparison.csv
```

Each script accepts `--only <project> ...` or `--kind image|release|maven` to run a subset;
`--kind image` gives the numbers for the 25 images. Finished projects are skipped on a rerun;
`--force` runs them again. Downloads are cached in `cache/` (or `$EMBEDTRACE_CACHE`).

## Output

`results/copies/<project>/findings.csv` has one row per candidate. `status` is `verified`, `unresolved: <failed check>`,
or `no embedded library (...)`. The evidence columns name the official build, build specification, symbol test, and
version source of each row. `summary.json` records the pinned target and the counts.
