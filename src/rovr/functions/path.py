import ctypes
import os
import stat
import subprocess
from os import path
import psutil
from lzstring import LZString
from rich.console import Console

from rovr.functions.icons import get_icon_for_file, get_icon_for_folder
from rovr.variables.constants import os_type

lzstring = LZString()
pprint = Console().print

config, pins = {}, {}


# ---------- Path Utilities ---------- #
def normalise(location: str | bytes) -> str:
    """Normalize path with forward slashes for consistency."""
    return path.normpath(location).replace("\\", "/").replace("//", "/")


# ---------- Hidden File Checks ---------- #
def is_hidden_file(filepath: str) -> bool:
    """Check if a file is hidden across platforms."""
    if os_type == "Windows":
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            return attrs != 0xFFFFFFFF and bool(attrs & 0x02)  # FILE_ATTRIBUTE_HIDDEN
        except (OSError, AttributeError):
            return False

    if os_type == "Darwin":
        name_hidden = path.basename(filepath).startswith(".")
        try:
            st = os.stat(filepath, follow_symlinks=False)
            flag_hidden = bool(getattr(st, "st_flags", 0) & getattr(stat, "UF_HIDDEN", 0))
        except OSError:
            flag_hidden = False
        return name_hidden or flag_hidden

    # Linux & others: dotfiles are hidden
    return path.basename(filepath).startswith(".")


# ---------- Compression Utilities ---------- #
def compress(text: str) -> str:
    return lzstring.compressToEncodedURIComponent(text)


def decompress(text: str) -> str:
    return lzstring.decompressFromEncodedURIComponent(text)


# ---------- File Operations ---------- #
def open_file(filepath: str) -> None:
    """Cross-platform file opener with default apps."""
    try:
        match os_type.lower():
            case "windows":
                os.startfile(filepath)  # type: ignore
            case "darwin":
                subprocess.run(["open", filepath], check=True)
            case _:
                subprocess.run(["xdg-open", filepath], check=True)
    except Exception as e:
        pprint(f"[red]Error opening file:[/] {e}")


def get_filtered_dir_names(cwd: str, show_hidden: bool = False) -> set[str]:
    """Return directory contents as names, optionally hiding hidden files."""
    try:
        return {
            item.name
            for item in os.scandir(cwd)
            if show_hidden or not is_hidden_file(item.path)
        }
    except (PermissionError, FileNotFoundError, OSError):
        raise PermissionError(f"Unable to access {cwd}")


def get_cwd_object(cwd: str, show_hidden: bool = False) -> tuple[list[dict], list[dict]]:
    """Return (folders, files) objects for a directory."""
    folders, files = [], []
    try:
        for item in os.scandir(cwd):
            if not show_hidden and is_hidden_file(item.path):
                continue
            target = {
                "name": item.name,
                "icon": get_icon_for_folder(item.name) if item.is_dir() else get_icon_for_file(item.name),
                "dir_entry": item,
            }
            (folders if item.is_dir() else files).append(target)
    except (PermissionError, FileNotFoundError, OSError):
        raise PermissionError(f"Unable to access {cwd}")

    return sorted(folders, key=lambda x: x["name"].lower()), sorted(files, key=lambda x: x["name"].lower())


def file_is_type(file_path: str) -> str:
    """Determine type of a given path."""
    try:
        mode = os.lstat(file_path).st_mode
    except (OSError, FileNotFoundError):
        return "unknown"

    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if os_type == "Windows" and hasattr(mode, "st_file_attributes") and mode.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:  # type: ignore
        return "junction"
    return "file"


def force_obtain_write_permission(item_path: str) -> bool:
    """Attempt to force write permission for a file or directory."""
    if not path.exists(item_path):
        return False
    try:
        os.chmod(item_path, stat.S_IMODE(os.lstat(item_path).st_mode) | stat.S_IWRITE)
        return True
    except (OSError, PermissionError) as e:
        pprint(f"[bright_red]Permission Error:[/] Failed to change permission for {item_path}: {e}")
        return False


def get_recursive_files(object_path: str, with_folders: bool = False):
    """Recursively return files (and optionally folders) from a path."""
    if path.isfile(object_path) or path.islink(object_path):
        entry = {"path": normalise(object_path), "relative_loc": path.basename(object_path)}
        return ([entry], []) if with_folders else [entry]

    files, folders = [], []
    for root, dirs, filenames in os.walk(object_path):
        if with_folders:
            folders.extend(normalise(path.join(root, d)) for d in dirs)
        files.extend(
            {
                "path": normalise(path.join(root, f)),
                "relative_loc": normalise(path.relpath(path.join(root, f), object_path + "/..")),
            }
            for f in filenames
        )
    return (files, folders) if with_folders else files


def ensure_existing_directory(directory: str) -> str:
    """Return the nearest existing parent directory."""
    while not (path.exists(directory) and path.isdir(directory)):
        parent = path.dirname(directory)
        if parent == directory:  # reached root
            break
        directory = parent
    return directory


# ---------- Mount Point Filters ---------- #
def _skip_fs(fstype: str, mountpoint: str, skip_types: tuple, skip_prefixes: tuple) -> bool:
    """Helper to decide whether to skip a filesystem/mountpoint."""
    return fstype in skip_types or mountpoint.startswith(skip_prefixes)


def _should_include_macos_mount_point(p) -> bool:
    return not _skip_fs(
        p.fstype, p.mountpoint,
        skip_types=("autofs", "devfs", "devtmpfs", "tmpfs"),
        skip_prefixes=("/System/Volumes/", "/System/", "/dev", "/private"),
    )


def _should_include_linux_mount_point(p) -> bool:
    return not _skip_fs(
        p.fstype, p.mountpoint,
        skip_types=(
            "autofs", "devfs", "devtmpfs", "tmpfs", "proc", "sysfs", "cgroup2", "debugfs",
            "tracefs", "fusectl", "configfs", "securityfs", "pstore", "bpf",
            "hugetlbfs", "mqueue", "devpts", "binfmt_misc",
        ),
        skip_prefixes=("/dev", "/proc", "/sys", "/run", "/boot", "/mnt/wslg", "/mnt/wsl"),
    )


def get_mounted_drives() -> list[str]:
    """Return user-relevant mounted drives depending on OS."""
    try:
        partitions = psutil.disk_partitions(all=False)
        if os_type == "Windows":
            return [normalise(p.mountpoint) for p in partitions if ":" in p.device]
        if os_type == "Darwin":
            return [p.mountpoint for p in partitions if _should_include_macos_mount_point(p)]
        return [p.mountpoint for p in partitions if _should_include_linux_mount_point(p)]
    except Exception as e:
        pprint(f"[red]Error getting mounted drives:[/] {e} -> fallback to home")
        return [path.expanduser("~")]
