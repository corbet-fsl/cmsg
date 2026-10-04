#!/usr/bin/env python3
"""Private exact Git source transport. No builds, scheduler, or credential export."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import re
import signal
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ORGS = ("corbet-foss", "corbet-labs", "corbet-libs", "cmtymeet")
OID = re.compile(r"[0-9a-f]{40}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 2 * 1024**3


class Refusal(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    """Only clean, exact first-party GitHub repository identities are accepted."""
    require(isinstance(value, str), "repository URL must be text")
    value = value.removeprefix("git+")
    for prefix in ("https://github.com/", "ssh://git@github.com/", "git@github.com:", "github:"):
        if value.startswith(prefix):
            tail = value[len(prefix):].removesuffix(".git")
            require(re.fullmatch(r"(?:" + "|".join(ORGS) + r")/[A-Za-z0-9][A-Za-z0-9_.-]*", tail)
                    and not tail.endswith("."), "foreign or malformed repository URL")
            return "https://github.com/" + tail
    raise Refusal("foreign or malformed repository URL")


def first_party(value):
    return isinstance(value, str) and any(
        prefix + org + "/" in value
        for prefix in ("github.com/", "github.com:", "github:") for org in ORGS)


def clean_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "GH_", "GITHUB_"))}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
               GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="/bin/false",
               GIT_AUTHOR_NAME="Source transport", GIT_AUTHOR_EMAIL="source@invalid",
               GIT_COMMITTER_NAME="Source transport", GIT_COMMITTER_EMAIL="source@invalid")
    return env


def git(repo, *args, network=False, binary=False):
    command = ["git", "--no-replace-objects", "--no-lazy-fetch", "-C", str(repo),
               "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
               "-c", "protocol.file.allow=always"]
    if network:
        command += ["-c", "credential.helper=!gh auth git-credential"]
    result = subprocess.run(command + list(args), env=clean_env(), capture_output=True,
                            timeout=180)
    require(result.returncode == 0, "Git operation refused or required objects unavailable (details suppressed)")
    return result.stdout if binary else result.stdout.decode().strip()


def data_at(repo, commit, path):
    return git(repo, "show", commit + ":" + path, binary=True)


def dependencies(path, raw):
    """Return canonical URLs and optional exact OIDs; retain caller's original bytes."""
    found = []
    if path.endswith("Cargo.lock"):
        for package in tomllib.loads(raw.decode()).get("package", []):
            source = package.get("source", "")
            if first_party(source):
                match = re.fullmatch(r"git\+(.+)\?branch=main#([0-9a-f]{40})", source)
                require(match is not None, "first-party Cargo lock must retain canonical branch=main identity")
                found.append((canonical(match[1]), match[2]))
    elif path.endswith("Cargo.toml"):
        def visit(value):
            if isinstance(value, dict):
                if isinstance(value.get("git"), str):
                    require(not value["git"].startswith("file:"),
                            "private Git file source needs its separate reviewed archive contract")
                if isinstance(value.get("path"), str):
                    relative = posixpath.normpath(posixpath.join(posixpath.dirname(path), value["path"]))
                    require(not relative.startswith(("/", "../")) and relative != "..",
                            "external path dependency needs its separate reviewed archive contract")
                if first_party(value.get("git")):
                    require(value.get("branch") == "main" and not {"rev", "tag", "path"}.intersection(value),
                            "first-party Cargo dependency must declare branch main")
                    found.append((canonical(value["git"]), None))
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
        visit(tomllib.loads(raw.decode()))
    elif path.endswith(("package.json", "package-lock.json", "npm-shrinkwrap.json")):
        def visit(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    # Repository/homepage metadata is not a dependency.
                    if key not in {"repository", "homepage", "bugs"}:
                        visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
            elif first_party(value):
                base, separator, ref = value.partition("#")
                require(separator and (ref == "main" or OID.fullmatch(ref)),
                        "npm first-party dependency needs main or exact lock OID")
                found.append((canonical(base), ref if OID.fullmatch(ref) else None))
        visit(json.loads(raw))
    return found


def tree_files(repo, commit):
    result = []
    for entry in git(repo, "ls-tree", "-rz", commit, binary=True).split(b"\0"):
        if not entry:
            continue
        info, name = entry.split(b"\t", 1)
        mode, kind, _ = info.decode().split()
        path = name.decode()
        require(mode != "160000", "Git dependency submodules require a separate exact source closure")
        if Path(path).name in {"Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "npm-shrinkwrap.json", ".gitattributes"}:
            require(mode in {"100644", "100755"}, "dependency metadata must be a regular file")
            raw = data_at(repo, commit, path)
            if path.endswith(".gitattributes"):
                require(b"filter=lfs" not in raw, "Git dependency LFS requires a separate materialized source closure")
            else:
                result.append((path, raw))
    return result


def read_tar(path, expected=None):
    require(Path(path).stat().st_size <= MAX_BYTES, "archive exceeds size limit")
    if expected:
        require(HEX.fullmatch(expected) and file_sha(path) == expected, "archive SHA256 mismatch")
    result = {}
    with tarfile.open(path, "r:") as archive:
        total = 0
        for member in archive:
            name = member.name
            require(not name.startswith("/") and ".." not in name.split("/") and "\\" not in name,
                    "unsafe archive path")
            if member.isdir():
                continue
            require(member.isfile() and name not in result, "archive contains link, special file, or duplicate")
            total += member.size
            require(total <= MAX_BYTES and len(result) < 20000, "archive exceeds limits")
            result[name] = archive.extractfile(member).read()
    return result


def source_identity(repo, commit, archive):
    require(OID.fullmatch(commit), "consumer commit must be exact")
    origin = canonical(git(repo, "remote", "get-url", "origin"))
    contents = read_tar(archive)
    with Path(archive).open("rb") as stream:
        check = subprocess.run(["git", "get-tar-commit-id"], stdin=stream, capture_output=True, env=clean_env())
    require(check.returncode == 0 and check.stdout.decode().strip() == commit, "consumer archive commit mismatch")
    metadata = tree_files(repo, commit)
    locks = {}
    for path, raw in metadata:
        require(contents.get(path) == raw, "consumer archive metadata differs from committed Git objects")
        locks[path] = sha(raw)
    require(any(Path(p).name in {"Cargo.lock", "package-lock.json", "npm-shrinkwrap.json"} for p in locks),
            "consumer needs a retained committed dependency lock")
    return {"url": origin, "commit": commit, "tree": git(repo, "rev-parse", commit + "^{tree}"),
            "source_sha256": file_sha(archive), "metadata_sha256": locks}, metadata


def produce(spec_path, output, check_main=False, allow_fetch=False):
    spec = json.loads(Path(spec_path).read_text())
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    repo_map = {}
    for url, path in spec["repositories"].items():
        key = canonical(url)
        require(key not in repo_map, "duplicate repository mapping")
        if path is None:
            require(check_main and allow_fetch, "remote-only source requires explicit main check and fetch")
            repo_map[key] = None
            continue
        require(canonical(git(path, "remote", "get-url", "origin")) == key, "local repository has foreign origin")
        require(git(path, "rev-parse", "--is-shallow-repository") == "false", "shallow source database refused")
        repo_map[key] = Path(path).resolve()
    manifest = {"schema": 1, "created_at": now(), "freshness": "main-observed" if check_main else "lock-only",
                "registry_resolution": "not-performed", "consumers": [], "repositories": []}
    needed = {}
    def enqueue(items):
        for url, oid in items:
            needed.setdefault(url, set())
            if oid:
                needed[url].add(oid)
        require(len(needed) <= 128, "source closure exceeds repository bound")
    for item in spec["consumers"]:
        identity, metadata = source_identity(item["repo"], item["commit"], item["source_archive"])
        manifest["consumers"].append(identity)
        for path, raw in metadata:
            enqueue(dependencies(path, raw))
    with tempfile.TemporaryDirectory(prefix="producer-", dir=output) as temporary:
        scratch = Path(temporary)
        states, scanned = {}, set()
        while True:
            pending = [(url, oid) for url, oids in needed.items() for oid in oids if (url, oid) not in scanned]
            unopened = [url for url in needed if url not in states]
            if not unopened and not pending:
                break
            for url in unopened:
                require(url in repo_map, "source closure needs unmapped repository: " + url)
                local = repo_map[url]
                name = sha(url.encode())[:24]
                isolated = scratch / name
                isolated.mkdir()
                git(isolated, "init", "--bare", "--template=", "--quiet")
                if local is not None:
                    objects = git(local, "rev-parse", "--path-format=absolute", "--git-path", "objects")
                    require("\n" not in objects and "\r" not in objects, "invalid Git object path")
                    (isolated / "objects/info/alternates").write_text(objects + "\n")
                observed = None
                if check_main:
                    line = git(isolated, "ls-remote", "--exit-code", url, "refs/heads/main", network=True)
                    fields = line.split()
                    require(len(fields) == 2 and OID.fullmatch(fields[0]) and fields[1] == "refs/heads/main", "main observation ambiguous")
                    main, observed = fields[0], now()
                else:
                    main = git(local, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
                states[url] = {"repo": isolated, "main": main, "observed_at": observed, "name": name}
                needed[url].add(main)
            for url, oids in list(needed.items()):
                state = states.get(url)
                if state is None:
                    continue
                for oid in list(oids):
                    if (url, oid) in scanned:
                        continue
                    try:
                        git(state["repo"], "cat-file", "-e", oid + "^{commit}")
                    except Refusal:
                        require(allow_fetch, "missing exact object; authenticated fetch was not enabled")
                        git(state["repo"], "fetch", "--no-tags", "--no-write-fetch-head", url, oid, network=True)
                    require(git(state["repo"], "rev-parse", oid + "^{commit}") == oid, "source OID mismatch")
                    scanned.add((url, oid))
                    for path, raw in tree_files(state["repo"], oid):
                        # Dependency lockfiles do not participate in consumer resolution.
                        if Path(path).name in {"Cargo.toml", "package.json"}:
                            enqueue(dependencies(path, raw))
        members = {"closure.py": Path(__file__).read_bytes()}
        for url, state in sorted(states.items()):
            isolated, commits = state["repo"], sorted(needed[url])
            git(isolated, "update-ref", "refs/heads/main", state["main"])
            refs = ["refs/heads/main"]
            trees = {}
            for oid in commits:
                ref = "refs/closure/" + oid
                git(isolated, "update-ref", ref, oid)
                refs.append(ref)
                trees[oid] = git(isolated, "rev-parse", oid + "^{tree}")
            bundle = scratch / (state["name"] + ".bundle")
            git(isolated, "-c", "pack.threads=1", "bundle", "create", "--version=2", str(bundle), *refs)
            (isolated / "objects/info/alternates").unlink(missing_ok=True)
            # Import into a fresh DB, proving full ancestry and object integrity.
            empty = scratch / (state["name"] + "-verify")
            empty.mkdir()
            verify_bundle(bundle, empty, state["main"], trees)
            member = "bundles/" + state["name"] + ".bundle"
            members[member] = bundle.read_bytes()
            manifest["repositories"].append({"url": url, "main": state["main"],
                "main_observed_at": state["observed_at"], "commits": trees,
                "bundle": member, "sha256": sha(members[member])})
        manifest["consumer_sha256"] = sha(members["closure.py"])
        members["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        destination = scratch / "closure.tar"
        with tarfile.open(destination, "w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in sorted(members.items()):
                header = tarfile.TarInfo(name)
                header.size, header.mode = len(raw), 0o644
                archive.addfile(header, io.BytesIO(raw))
        digest = file_sha(destination)
        final = output / (digest + ".tar")
        if final.exists():
            require(file_sha(final) == digest, "content address collision")
        else:
            destination.rename(final)
        (output / (digest + ".json")).write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        return {"archive": str(final), "sha256": digest, "repositories": len(states),
                "freshness": manifest["freshness"], "registry_resolution": "not-performed"}


def verify_bundle(bundle, repo, main, commits):
    require(OID.fullmatch(main) and isinstance(commits, dict) and main in commits,
            "invalid bundle identity")
    require(all(OID.fullmatch(oid) and OID.fullmatch(tree) for oid, tree in commits.items()), "invalid object identity")
    git(repo, "init", "--bare", "--template=", "--quiet")
    git(repo, "bundle", "verify", str(bundle))
    heads = dict(line.split(" ", 1)[::-1] for line in git(repo, "bundle", "list-heads", str(bundle)).splitlines())
    expected = {"refs/heads/main": main, **{"refs/closure/" + oid: oid for oid in commits}}
    require(heads == expected, "bundle advertises unexpected refs")
    git(repo, "fetch", "--no-tags", str(bundle), "+refs/heads/main:refs/heads/main", "+refs/closure/*:refs/closure/*")
    git(repo, "fsck", "--full", "--strict", "--no-reflogs")
    for oid, tree in commits.items():
        require(git(repo, "rev-parse", oid + "^{commit}") == oid and
                git(repo, "rev-parse", oid + "^{tree}") == tree, "bundle tree or commit mismatch")
    git(repo, "symbolic-ref", "HEAD", "refs/heads/main")
    require(git(repo, "rev-parse", "HEAD^{commit}") == main,
            "closure HEAD differs from observed original main")


def worker_env(repositories, root):
    env = clean_env()
    settings = [("credential.helper", ""), ("core.hooksPath", "/dev/null"),
                ("protocol.ext.allow", "never"), ("protocol.file.allow", "always")]
    for org in ORGS:
        for prefix in ("https://github.com/", "ssh://git@github.com/", "git@github.com:"):
            settings.append(("url." + (root / "UNSTAGED").as_uri() + "/.insteadOf", prefix + org + "/"))
    for url, repo in repositories.items():
        tail = canonical(url).removeprefix("https://github.com/")
        for prefix in ("https://github.com/", "ssh://git@github.com/", "git@github.com:"):
            for suffix in ("", ".git"):
                settings.append(("url." + repo.as_uri() + ".insteadOf", prefix + tail + suffix))
    env["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (key, value) in enumerate(settings):
        env["GIT_CONFIG_KEY_" + str(index)] = key
        env["GIT_CONFIG_VALUE_" + str(index)] = value
    env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"
    return env


def consume(archive, digest, source_archive, source_digest, commit, repository, scratch, command):
    payload = read_tar(archive, digest)
    require("manifest.json" in payload and "closure.py" in payload, "closure metadata missing")
    manifest = json.loads(payload["manifest.json"])
    require(manifest.get("schema") == 1 and sha(payload["closure.py"]) == manifest.get("consumer_sha256"), "consumer identity mismatch")
    expected_members = {"manifest.json", "closure.py"}
    identities = [c for c in manifest["consumers"] if c["commit"] == commit and c["url"] == canonical(repository)
                  and c["source_sha256"] == source_digest]
    require(len(identities) == 1, "consumer archive is not bound to closure")
    source = read_tar(source_archive, source_digest)
    for path, expected in identities[0]["metadata_sha256"].items():
        require(path in source and sha(source[path]) == expected, "retained source metadata or lock differs")
    require(Path(scratch).is_dir(), "worker scratch parent must exist")
    with tempfile.TemporaryDirectory(prefix="dependency-closure-", dir=scratch) as temporary:
        root, repos = Path(temporary), {}
        for index, item in enumerate(manifest["repositories"]):
            url = canonical(item["url"])
            require(item["url"] == url and url not in repos, "foreign or duplicate source identity")
            member = item["bundle"]
            require(re.fullmatch(r"bundles/[0-9a-f]{24}\.bundle", member) and member not in expected_members,
                    "invalid bundle member")
            expected_members.add(member)
            require(member in payload and sha(payload[member]) == item["sha256"], "bundle digest mismatch")
            bundle = root / (str(index) + ".bundle")
            bundle.write_bytes(payload[member])
            repo = root / (str(index) + ".git")
            repo.mkdir()
            verify_bundle(bundle, repo, item["main"], item["commits"])
            repos[url] = repo
        require(set(payload) == expected_members, "unexpected closure archive members")
        # Re-derive locked OIDs, so the manifest cannot omit a required source.
        for path in identities[0]["metadata_sha256"]:
            for url, oid in dependencies(path, source[path]):
                require(url in repos, "source closure is incomplete")
                if oid:
                    git(repos[url], "cat-file", "-e", oid + "^{commit}")
        require(command, "worker requires an explicit command")
        receipt = root / "manifest.json"
        receipt.write_bytes(payload["manifest.json"])
        env = worker_env(repos, root)
        env["DEPENDENCY_CLOSURE_MANIFEST"] = str(receipt)
        env["DEPENDENCY_CLOSURE_SHA256"] = digest
        child = subprocess.Popen(command, env=env)
        # Preserve ccid's existing supervisor cleanup when Crow stops this wrapper.
        previous = {}
        def forward(signum, _frame):
            if child.poll() is None:
                child.send_signal(signum)
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, forward)
            return child.wait()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    producer = sub.add_parser("produce")
    producer.add_argument("--spec", required=True)
    producer.add_argument("--out", required=True)
    producer.add_argument("--check-main", action="store_true")
    producer.add_argument("--allow-fetch", action="store_true")
    worker = sub.add_parser("consume")
    for key in ("archive", "sha256", "source-archive", "source-sha256", "commit", "repository", "scratch"):
        worker.add_argument("--" + key, required=True)
    worker.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.action == "produce":
            print(json.dumps(produce(args.spec, args.out, args.check_main, args.allow_fetch), sort_keys=True))
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        return consume(args.archive, args.sha256, args.source_archive, args.source_sha256,
                       args.commit, args.repository, args.scratch, command)
    except (Refusal, ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired, tarfile.TarError) as error:
        # Git stderr and local configuration never enter output.
        print("source closure refused: " + (str(error) if isinstance(error, Refusal) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
