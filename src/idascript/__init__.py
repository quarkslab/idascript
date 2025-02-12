import sys
import os
from pathlib import Path
import logging

IDA_PATH_ENV = "IDA_PATH"

IDA_BINARY = None

def __get_names() -> list[str]:
    names = ["idat64", "idat"]
    if sys.platform == "win32":
        return [x+".exe" for x in names]
    else:
        return names


def __check_environ() -> bool:
    global IDA_BINARY
    if IDA_PATH_ENV in os.environ:
        for bin_name in __get_names():
            full_path = Path(os.environ[IDA_PATH_ENV]) / bin_name
            if full_path.exists():
                IDA_BINARY = full_path.resolve()
                return True
    return False


def __check_path() -> bool:
    global IDA_BINARY
    if "PATH" in os.environ:
        for p in os.environ["PATH"].split(":"):
            for bin_name in __get_names():
                if (Path(p) / bin_name).exists():
                    IDA_BINARY = (Path(p) / bin_name).resolve()
                    return True
    return False


if not __check_environ():
    if not __check_path():
        logging.warning("IDA Pro executable not found, should be in $PATH or IDA_PATH env variable")


def is_headless() -> bool:
    import psutil
    current_process = psutil.Process()
    process_name = current_process.name()
    return process_name.startswith("idat")


from idascript.ida import IDA, MultiIDA, TIMEOUT_RETURNCODE
from idascript.utils import iter_binary_files
