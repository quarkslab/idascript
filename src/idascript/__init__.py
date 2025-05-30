from pathlib import Path

from idascript.ida import IDA, MultiIDA, TIMEOUT_RETURNCODE, IDA_PATH_ENV, get_ida_path, NOP_SCRIPT
from idascript.utils import iter_binary_files



def is_headless() -> bool:
    import psutil
    current_process = psutil.Process()
    process_name = current_process.name()
    return process_name.startswith("idat")


__all__ = [
    "IDA",
    "MultiIDA",
    "TIMEOUT_RETURNCODE",
    "iter_binary_files",
    "IDA_PATH_ENV",
    "get_ida_path",
    "NOP_SCRIPT",
    "is_headless"
]
