"""Archive exact committed source, local submodule commits and verified LFS objects.

Never fetch or smudge from the network. Missing source dependencies fail closed.
"""
import copy
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


class SourceFailure(Exception):
    pass


def git(repo, *args):
    result = subprocess.run(["git", "--no-lazy-fetch", "-C", str(repo), *args], capture_output=True, text=True,
                            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
    if result.returncode:
        raise SourceFailure("Required committed source or local dependency checkout is unavailable")
    return result.stdout.strip()


def submodules(repo, commit):
    result = {}
    for record in git(repo, "ls-tree", "-r", "-z", commit).split("\0"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode, _, revision = metadata.split()
        if mode == "160000":
            if Path(path).is_absolute() or ".." in Path(path).parts:
                raise SourceFailure("Unsafe submodule path")
            result[path] = revision
    return result


def pointer(data):
    if not data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
        return None
    match = re.fullmatch(rb"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n?", data)
    if not match:
        raise SourceFailure("Unsupported or malformed Git LFS pointer; source was not staged")
    return match[1].decode(), int(match[2])


def dependency_checkout(repository, path, revision):
    # An isolated worktree need not duplicate initialized submodules. Only reuse
    # checkouts belonging to this same parent repository, at the exact gitlink.
    worktrees = [repository]
    for record in git(repository, "worktree", "list", "--porcelain", "-z").split("\0"):
        if record.startswith("worktree "):
            worktrees.append(Path(record[len("worktree "):]))
    for worktree in dict.fromkeys(worktrees):
        child = (worktree / path).resolve()
        if not child.is_dir():
            continue
        try:
            if Path(git(child, "rev-parse", "--show-toplevel")).resolve() != child:
                continue
            git(child, "cat-file", "-e", revision + "^{commit}")
            return child
        except SourceFailure:
            continue
    raise SourceFailure(f"Required exact local submodule checkout missing: {path}")


def create(repo, commit, destination):
    repo, destination = Path(repo).resolve(), Path(destination)
    stats = {"submodules": [], "lfs_objects": 0, "lfs_bytes": 0}
    media_roots = {}
    with tempfile.TemporaryDirectory(prefix="source-closure-", dir=destination.parent) as temporary:
        temporary = Path(temporary)
        output = temporary / "complete.tar"
        sequence = 0

        def lfs_snapshot(repository, oid, size, name):
            if repository not in media_roots:
                # Git LFS resolves configured storage and linked-worktree paths;
                # `env` reads configuration only and never transfers objects.
                lines = git(repository, "lfs", "env").splitlines()
                value = next((line[len("LocalMediaDir="):] for line in lines if line.startswith("LocalMediaDir=")), None)
                if not value:
                    raise SourceFailure("Cannot locate the existing local Git LFS object cache")
                media_roots[repository] = Path(value)
            cached = media_roots[repository] / oid[:2] / oid[2:4] / oid
            if not cached.is_file() or cached.is_symlink():
                raise SourceFailure(f"Local Git LFS object missing for {name}: sha256:{oid}; fetch this exact object before dispatch")
            snapshot = tempfile.SpooledTemporaryFile(max_size=1024 * 1024, dir=temporary)
            try:
                digest, count = hashlib.sha256(), 0
                with cached.open("rb") as source:
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        count += len(block)
                        if count > size:
                            raise SourceFailure(f"Git LFS size mismatch for {name}")
                        digest.update(block)
                        snapshot.write(block)
                if count != size or digest.hexdigest() != oid:
                    raise SourceFailure(f"Git LFS content mismatch for {name}")
                snapshot.seek(0)
                return snapshot
            except BaseException:
                snapshot.close()
                raise

        with tarfile.open(output, "w", format=tarfile.PAX_FORMAT, pax_headers={"comment": commit}) as result:
            def append(repository, revision, prefix="", depth=0):
                nonlocal sequence
                if depth > 8:
                    raise SourceFailure("Nested submodule depth exceeds the supported source closure")
                modules = submodules(repository, revision)
                sequence += 1
                archive_path = temporary / f"git-{sequence}.tar"
                # Git archive can apply configured worktree filters, including
                # Git LFS smudge. Disable them so only our verified local-object
                # hydration runs; missing data must never cause an implicit fetch.
                keys = git(repository, "config", "--null", "--name-only", "--list").split("\0")
                filters = sorted({key.rsplit(".", 1)[0] for key in keys
                                  if re.fullmatch(r"filter\..+\.(?:smudge|process|required)", key)})
                overrides = []
                for name in filters:
                    overrides.extend(["-c", name + ".smudge=", "-c", name + ".process=",
                                      "-c", name + ".required=false"])
                git(repository, *overrides, "archive", "--format=tar", "--output=" + str(archive_path), revision)
                exported_modules = set()
                with tarfile.open(archive_path, "r:") as source:
                    for original in source:
                        relative = original.name.rstrip("/")
                        if relative in modules:
                            exported_modules.add(relative)
                            continue
                        entry = copy.copy(original)
                        entry.name = prefix + original.name
                        entry.pax_headers = {k: v for k, v in original.pax_headers.items() if k not in {"comment", "path", "linkpath"}}
                        if entry.islnk():
                            entry.linkname = prefix + original.linkname
                        if not entry.isfile():
                            result.addfile(entry)
                            continue
                        with source.extractfile(original) as data:
                            small = data.read() if original.size <= 4096 else None
                            lfs = pointer(small) if small is not None else None
                            if lfs:
                                oid, size = lfs
                                with lfs_snapshot(repository, oid, size, entry.name) as payload:
                                    entry.size = size
                                    result.addfile(entry, payload)
                                stats["lfs_objects"] += 1
                                stats["lfs_bytes"] += size
                            else:
                                result.addfile(entry, io.BytesIO(small) if small is not None else data)
                for path in sorted(exported_modules):
                    revision = modules[path]
                    child = dependency_checkout(repository, path, revision)
                    stats["submodules"].append({"path": prefix + path, "commit": revision})
                    append(child, revision, prefix + path + "/", depth + 1)
            append(repo, commit)
        os.replace(output, destination)
    return stats
