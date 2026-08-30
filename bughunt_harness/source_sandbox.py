"""Disposable, semantic source execution with network and secret isolation.

There is deliberately no command-string API.  Commands are selected from
project metadata and fixed templates.  Repository code never runs during
normal source registration/indexing.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .errors import StateError
from .redact import redact_text


@dataclass(frozen=True)
class SandboxLimits:
    cpu_seconds: int = 60
    memory_mb: int = 512
    disk_mb: int = 256
    process_count: int = 64
    wall_seconds: int = 120

    def bounded(self) -> "SandboxLimits":
        return SandboxLimits(
            cpu_seconds=max(1, min(int(self.cpu_seconds), 600)),
            memory_mb=max(64, min(int(self.memory_mb), 4096)),
            disk_mb=max(32, min(int(self.disk_mb), 2048)),
            process_count=max(8, min(int(self.process_count), 256)),
            wall_seconds=max(1, min(int(self.wall_seconds), 1800)),
        )


def detect_sandbox_backend() -> dict:
    bwrap, podman, docker = shutil.which("bwrap"), shutil.which("podman"), shutil.which("docker")
    # Only advertise a backend that this semantic executor can actually use.
    # Container engines stay visible as future adapter candidates; they never
    # become an implicit generic-container fallback.
    selected = "bubblewrap" if bwrap else ""
    return {
        "available": bool(selected), "backend": selected,
        "bubblewrap": bwrap or "", "podman": podman or "", "docker": docker or "",
        "container_candidates": [name for name, path in (("podman", podman), ("docker", docker)) if path],
        "network_isolation": bool(selected), "resource_controls": bool(selected),
        "secret_isolation": bool(selected), "host_docker_socket_mounted": False,
        "ephemeral_writable_worktree": bool(selected),
        "isolated_home_tmp_cache": bool(selected),
        "aggregate_disk_watchdog": bool(selected),
        "cpu_memory_process_wall_limits": bool(selected),
        "dependency_mode": "offline_only",
    }


class SourceSandboxExecutor:
    ACTIONS = {
        "build": "source_build", "test": "source_test", "reproducer": "source_reproducer",
        "fuzz": "source_fuzz", "start_local_service": "source_start_local_service",
        "codeql_database": "source_static_analysis",
    }

    def __init__(self, ctx) -> None:
        self.ctx = ctx

    def plan(self, repository: int | str, operation: str, *, entrypoint: str = "") -> dict:
        from .source import SourceService

        if operation not in self.ACTIONS:
            raise StateError(f"unsupported sandbox operation: {operation}")
        repo, snapshot = SourceService(self.ctx).snapshot(repository)
        command, reason = self._select_command(snapshot, operation, entrypoint)
        policy_action = self.ACTIONS[operation]
        if operation == "codeql_database" and reason.startswith("BUILD_REQUIRED"):
            policy_action = "source_build"
        decision = self.ctx.policy.check(policy_action).as_dict()
        return {
            "repository_id": repo["repository_id"], "commit": repo["resolved_commit"],
            "operation": operation, "policy_action": policy_action,
            "decision": decision, "command_template": command, "selection_reason": reason,
            "network": "disabled", "source_mount": "read_only",
            "worktree": "ephemeral_writable_copy", "output_mount": "controlled_write_only",
        }

    def execute(
        self, repository: int | str, operation: str, *, session_id: int,
        approval_id: int | None = None, entrypoint: str = "",
        limits: SandboxLimits | None = None,
    ) -> dict:
        from .source import SourceService

        plan = self.plan(repository, operation, entrypoint=entrypoint)
        if plan["decision"]["decision"] == "deny":
            raise StateError(f"sandbox action denied: {plan['decision']['reason']}")
        if plan["decision"]["decision"] == "approval_required":
            if approval_id is None:
                approval = self.ctx.db.request_approval(
                    plan["policy_action"], f"source:{plan['repository_id']}@{plan['commit']}",
                    requested_by="whitebox-audit-specialist", note=f"sandbox {operation}: {plan['selection_reason']}",
                    program=self.ctx.slug, method="SOURCE_SANDBOX", session_id=session_id,
                    constraints={"max_requests": 1, "max_concurrency": 1,
                                 "duration_seconds": (limits or SandboxLimits()).bounded().wall_seconds},
                )
                return {**plan, "mode": "ASK", "approval": approval.public_id, "executed": False}
            approval = self.ctx.db.get_approval(approval_id)
            if approval.status != "approved" or approval.action != plan["policy_action"] or approval.session_id != session_id:
                raise StateError("sandbox approval is not approved and bound to this session/action")
            self.ctx.db.record_approval_use(approval.id)
        repo, snapshot = SourceService(self.ctx).snapshot(repository)
        bounded = (limits or SandboxLimits()).bounded()
        backend = detect_sandbox_backend()
        if backend["backend"] != "bubblewrap":
            raise StateError("bubblewrap is required for the current local source sandbox implementation")
        output_root = self.ctx.workspace / "source" / "sandbox-output"
        output_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="run-", dir=output_root) as raw_output:
            run_root = Path(raw_output)
            work, output = run_root / "work", run_root / "out"
            sandbox_home, sandbox_tmp = run_root / "home", run_root / "tmp"
            shutil.copytree(snapshot, work, symlinks=False)
            for directory in (output, sandbox_home, sandbox_tmp, sandbox_home / ".cache"):
                directory.mkdir(parents=True, exist_ok=True)
            offline_cache = (
                self.ctx.workspace / "source" / "dependency-cache" /
                repo["repository_id"] / repo["resolved_commit"]
            )
            if offline_cache.is_dir():
                shutil.copytree(
                    offline_cache, sandbox_home / ".cache", dirs_exist_ok=True,
                    symlinks=False,
                )
            argv = self._bwrap_argv(
                snapshot, work, output, sandbox_home, sandbox_tmp,
                plan["command_template"],
            )
            env = {
                "PATH": "/usr/bin:/bin", "HOME": "/home/sandbox", "TMPDIR": "/tmp",
                "XDG_CACHE_HOME": "/home/sandbox/.cache",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                "NO_PROXY": "*", "no_proxy": "*",
            }
            try:
                completed, disk_exceeded = self._run_with_disk_watchdog(
                    argv, env, bounded, run_root,
                )
                timed_out = False
            except subprocess.TimeoutExpired as exc:
                completed = None; timed_out = True; disk_exceeded = False
                stdout, stderr, returncode = exc.stdout or "", exc.stderr or "", -1
            else:
                stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
            record = {
                **plan, "executed": True, "mode": "AUTO", "backend": "bubblewrap",
                "returncode": returncode, "timed_out": timed_out,
                "stdout": redact_text(str(stdout))[:100_000], "stderr": redact_text(str(stderr))[:100_000],
                "limits": bounded.__dict__, "host_home_mounted": False,
                "network_enabled": False, "host_docker_socket_mounted": False,
                "ephemeral_writable_worktree": True,
                "offline_dependency_cache": offline_cache.is_dir(),
                "aggregate_disk_enforced": True, "disk_limit_exceeded": disk_exceeded,
            }
            if operation == "codeql_database" and returncode == 0 and not disk_exceeded:
                database_source = output / "codeql-db"
                if not database_source.is_dir():
                    raise StateError("CodeQL reported success without producing /out/codeql-db")
                destination = (
                    self.ctx.workspace / "source" / "indexes" / repo["repository_id"] /
                    f"codeql-{repo['resolved_commit'][:12]}"
                )
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    shutil.rmtree(destination)
                shutil.copytree(database_source, destination, symlinks=False)
                record["database"] = destination.name
                record["database_path"] = str(destination)
            artifact = self.ctx.workspace / "source" / "analysis" / f"sandbox-{repo['repository_id']}-{repo['resolved_commit'][:12]}-{operation}.json"
            artifact.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
            observation = SourceService(self.ctx).create_observation(
                repo["id"], observation_type="sandbox_execution", file=".",
                observation=f"Sandbox {operation} exited {returncode}; this is source evidence, not automatically a Finding.",
                source_skill="source-dataflow-analysis", confidence=0.7 if returncode == 0 else 0.4,
                metadata={"artifact_ref": str(artifact.relative_to(self.ctx.workspace)),
                          "operation": operation, "network": "disabled", "timed_out": timed_out},
            )
            record.update({"artifact": str(artifact), "observation": observation["public_id"]})
            return record

    @staticmethod
    def _select_command(snapshot: Path, operation: str, entrypoint: str) -> tuple[list[str], str]:
        if operation == "codeql_database":
            codeql = shutil.which("codeql")
            if not codeql:
                raise StateError("CodeQL is not installed")
            language, build_mode, build_command = SourceSandboxExecutor._codeql_project_mode(snapshot)
            command = [
                str(Path(codeql).resolve()), "database", "create", "/out/codeql-db",
                f"--language={language}", "--source-root=/work", "--threads=1",
            ]
            if build_mode == "none":
                command.append("--build-mode=none")
                return command, f"NO_BUILD language={language}; static extraction only"
            command.append(f"--command={build_command}")
            return command, f"BUILD_REQUIRED language={language}; known offline template={build_command}"
        if operation == "reproducer":
            rel = PurePosixPath(entrypoint)
            if rel.is_absolute() or ".." in rel.parts or rel.suffix not in {".py", ".js", ".rb"}:
                raise StateError("reproducer entrypoint must be a relative .py/.js/.rb file")
            if not (snapshot / Path(*rel.parts)).is_file():
                raise StateError("reproducer entrypoint is absent from the pinned snapshot")
            runtime = {".py": "/usr/bin/python3", ".js": "/usr/bin/node", ".rb": "/usr/bin/ruby"}[rel.suffix]
            return [runtime, "-I", f"/src/{rel}"] if rel.suffix == ".py" else [runtime, f"/src/{rel}"], "explicit bounded reproducer file"
        if operation == "test":
            if (snapshot / "pytest.ini").exists() or (snapshot / "pyproject.toml").exists() or (snapshot / "tests").is_dir():
                return ["/usr/bin/python3", "-I", "-m", "pytest", "-q", "-p", "no:cacheprovider", "/src"], "Python test metadata"
            if (snapshot / "package.json").exists(): return ["/usr/bin/npm", "test", "--", "--runInBand"], "Node package test script"
            if (snapshot / "go.mod").exists(): return ["/usr/bin/go", "test", "./..."], "Go module"
            raise StateError("no supported test template can be derived from project metadata")
        if operation == "build":
            if (snapshot / "pyproject.toml").exists(): return ["/usr/bin/python3", "-I", "-m", "compileall", "-q", "/src"], "Python compile-only build"
            if (snapshot / "package.json").exists(): return ["/usr/bin/npm", "run", "build", "--if-present"], "Node build script without install"
            if (snapshot / "go.mod").exists(): return ["/usr/bin/go", "build", "./..."], "Go module build"
            raise StateError("no supported build template can be derived from project metadata")
        if operation == "fuzz":
            rel = PurePosixPath(entrypoint)
            if rel.is_absolute() or ".." in rel.parts or rel.suffix != ".py" or not (snapshot / Path(*rel.parts)).is_file():
                raise StateError("fuzz entrypoint must be an existing relative Python harness")
            return ["/usr/bin/python3", "-I", f"/src/{rel}", "--max-runs", "1000"], "bounded Python fuzz harness"
        raise StateError("local service startup requires a separately implemented framework-specific template")

    @staticmethod
    def _codeql_project_mode(snapshot: Path) -> tuple[str, str, str]:
        suffixes = {path.suffix.lower() for path in snapshot.rglob("*") if path.is_file()}
        if suffixes & {".py"}:
            return "python", "none", ""
        if suffixes & {".js", ".jsx", ".ts", ".tsx"}:
            return "javascript-typescript", "none", ""
        if suffixes & {".rb"}:
            return "ruby", "none", ""
        if (snapshot / "go.mod").is_file():
            return "go", "build", "/usr/bin/go build ./..."
        if (snapshot / "pom.xml").is_file():
            return "java-kotlin", "build", "/usr/bin/mvn -o -DskipTests package"
        if (snapshot / "gradlew").is_file() or (snapshot / "build.gradle").is_file() or (snapshot / "build.gradle.kts").is_file():
            return "java-kotlin", "build", "/work/gradlew --offline assemble"
        raise StateError("CodeQL language/build mode cannot be derived from supported project metadata")

    @staticmethod
    def _bwrap_argv(
        snapshot: Path, work: Path, output: Path, sandbox_home: Path,
        sandbox_tmp: Path, command: list[str],
    ) -> list[str]:
        command = [value.replace("/src/", "/work/").replace("/src", "/work") for value in command]
        argv = [
            shutil.which("bwrap") or "bwrap", "--die-with-parent", "--new-session",
            "--unshare-all", "--unshare-net", "--clearenv", "--proc", "/proc", "--dev", "/dev",
            "--dir", "/home", "--dir", "/home/sandbox",
        ]
        for root in ("/usr", "/bin", "/lib", "/lib64", "/etc"):
            if Path(root).exists(): argv.extend(["--ro-bind", root, root])
        executable = Path(command[0]) if command and Path(command[0]).is_absolute() else None
        if executable and executable.exists() and not any(str(executable).startswith(root + "/") for root in ("/usr", "/bin", "/lib", "/lib64", "/etc")):
            tool_root = executable.resolve().parent
            argv.extend(["--ro-bind", str(tool_root), str(tool_root)])
        argv.extend([
            "--ro-bind", str(snapshot), "/src-original", "--bind", str(work), "/work",
            "--bind", str(output), "/out", "--bind", str(sandbox_home), "/home/sandbox",
            "--bind", str(sandbox_tmp), "/tmp", "--chdir", "/work",
            "--setenv", "HOME", "/home/sandbox", "--setenv", "TMPDIR", "/tmp",
            "--setenv", "XDG_CACHE_HOME", "/home/sandbox/.cache",
            "--setenv", "PATH", "/usr/bin:/bin", "--", *command,
        ])
        return argv

    @staticmethod
    def _directory_size(root: Path) -> int:
        total = 0
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
            except OSError:
                continue
        return total

    @classmethod
    def _run_with_disk_watchdog(cls, argv, env, limits: SandboxLimits, run_root: Path):
        ceiling = limits.disk_mb * 1024 * 1024
        if cls._directory_size(run_root) > ceiling:
            raise StateError("sandbox source/worktree already exceeds aggregate disk limit")
        process = subprocess.Popen(
            argv, cwd="/", env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, preexec_fn=lambda: cls._apply_limits(limits),
        )
        deadline = time.monotonic() + limits.wall_seconds
        disk_exceeded = False
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    process.kill(); process.communicate()
                    raise subprocess.TimeoutExpired(argv, limits.wall_seconds)
                if cls._directory_size(run_root) > ceiling:
                    disk_exceeded = True
                    process.kill(); stdout, stderr = process.communicate()
                    break
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr), disk_exceeded

    @staticmethod
    def _apply_limits(limits: SandboxLimits) -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        memory = limits.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        # RLIMIT_NPROC is per real UID, not per process tree.  Account for the
        # host user's already-running processes while still bounding additional
        # children this sandbox can create.
        existing = 0
        uid = os.getuid()
        for status in Path("/proc").glob("[0-9]*/status"):
            try:
                if f"Uid:\t{uid}\t" in status.read_text(encoding="utf-8", errors="ignore"):
                    # Linux accounts threads, not just process leaders, for
                    # RLIMIT_NPROC.
                    existing += len(list(status.parent.joinpath("task").glob("[0-9]*"))) or 1
            except OSError:
                continue
        process_ceiling = existing + limits.process_count
        resource.setrlimit(resource.RLIMIT_NPROC, (process_ceiling, process_ceiling))
        file_bytes = limits.disk_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))


__all__ = ["SandboxLimits", "SourceSandboxExecutor", "detect_sandbox_backend"]
