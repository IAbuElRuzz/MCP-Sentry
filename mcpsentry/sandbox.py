"""Fixed Docker isolation profile. No arbitrary Docker flags or host networking."""

from pathlib import Path
import re
import stat


def validate(config, base):
    if not isinstance(config, dict) or set(config) - {"image", "mounts", "workdir", "memory_mb", "pids_limit"}:
        raise ValueError("Invalid sandbox configuration")
    image = config.get("image", "")
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,255}", image):
        raise ValueError("Sandbox requires a Docker image reference")
    workdir = config.get("workdir", "/workspace")
    if not isinstance(workdir, str) or not workdir.startswith("/") or any(c in workdir for c in ("\n", "\r", "\x00")):
        raise ValueError("Sandbox workdir must be an absolute container path")
    for key, default, low, high in (("memory_mb", 256, 32, 4096), ("pids_limit", 64, 8, 256)):
        value = config.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"Invalid sandbox {key}")
    mounts = config.get("mounts", [])
    if not isinstance(mounts, list) or len(mounts) > 16:
        raise ValueError("Sandbox supports at most 16 read-only mounts")
    targets = set()
    for mount in mounts:
        if not isinstance(mount, dict) or set(mount) != {"source", "target"} or not all(isinstance(x, str) for x in mount.values()):
            raise ValueError("Sandbox mounts require source and target")
        source = (Path(base) / mount["source"]).resolve()
        target = mount["target"]
        if not source.is_file() or stat.S_ISSOCK(source.stat().st_mode):
            raise ValueError("Sandbox mounts must be individual regular files; bake code directories into the image")
        if not target.startswith("/") or any(c in str(source) + target for c in (",", "\n", "\r", "\x00")) or ".." in Path(target).parts:
            raise ValueError("Invalid sandbox mount path")
        if target in targets or any(target == p or target.startswith(p + "/") for p in ("/proc", "/sys", "/dev", "/run", "/tmp")):
            raise ValueError("Sandbox mount target is reserved or duplicated")
        targets.add(target)
        mount["source"] = str(source)


def protect_state(config, state_directory):
    state = Path(state_directory).resolve()
    for mount in config.get("mounts", []):
        source = Path(mount["source"]).resolve()
        if source == state or source in state.parents or state in source.parents:
            raise ValueError("Sandbox mounts must not expose the gateway state or approval key")


def command(spec, container_name, env_file=None):
    profile = spec["sandbox"]
    args = ["docker", "--context", "default", "run", "--rm", "--interactive", "--pull=never", "--name", container_name,
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--user=65534:65534", "--pids-limit=" + str(profile.get("pids_limit", 64)),
            "--memory=" + str(profile.get("memory_mb", 256)) + "m", "--memory-swap=" + str(profile.get("memory_mb", 256)) + "m",
            "--cpus=1", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m", "--workdir", profile.get("workdir", "/workspace")]
    for mount in profile.get("mounts", []):
        args.extend(["--mount", f"type=bind,source={mount['source']},target={mount['target']},readonly"])
    if spec.get("env"):
        args.extend(["--env-file", env_file or "<private-env-descriptor>"])
    args.extend(["--entrypoint", spec["command"], profile["image"], *spec.get("args", [])])
    return args
