import sys
import os
from pathlib import Path

IDA_PATH_ENV = "IDA_PATH"
BIN_NAME = "idat64.exe" if sys.platform == "win32" else "idat64"

IDA_BINARY = None


def __check_environ() -> bool:
    global IDA_BINARY
    if IDA_PATH_ENV in os.environ:
        if (Path(os.environ[IDA_PATH_ENV]) / BIN_NAME).exists():
            IDA_BINARY = (Path(os.environ[IDA_PATH_ENV]) / BIN_NAME).resolve()
            return True
    return False


def __check_path() -> bool:
    global IDA_BINARY
    if "PATH" in os.environ:
        for p in os.environ["PATH"].split(":"):
            if (Path(p) / BIN_NAME).exists():
                IDA_BINARY = (Path(p) / BIN_NAME).resolve()
                return True
    return False

if not __check_environ():
    if not __check_path():
        raise ImportError("IDA Pro executable not found, should be in $PATH or IDA_PATH env variable")

from idascript.ida import IDA, MultiIDA, TIMEOUT_RETURNCODE
from idascript.utils import iter_binary_files
