import sys
import os
from pathlib import Path

IDAROOT_ENV = "IDAROOT"
BIN_NAME = "idat64.exe" if sys.platform == "win32" else "idat64"

IDA_BINARY = None


def __check_environ() -> bool:
    global IDA_BINARY
    if IDAROOT_ENV in os.environ:
        if (Path(os.environ[IDAROOT_ENV]) / BIN_NAME).exists():
            IDA_BINARY = (Path(os.environ[IDAROOT_ENV]) / BIN_NAME).absolute()
            return True
    return False


def __check_path() -> bool:
    global IDA_BINARY
    if "PATH" in os.environ:
        for p in os.environ["PATH"].split(":"):
            if (Path(p) / BIN_NAME).exists():
                IDA_BINARY = (Path(os.environ[IDAROOT_ENV]) / BIN_NAME).absolute()
                return True
    return False


if not __check_environ():
    if not __check_path():
        raise ImportError("IDA Pro executable not found, should be in $PATH or IDAROOT env variable")

from idascript.ida import IDA, MultiIDA
from idascript.utils import iter_binary_files