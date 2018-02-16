import os
import sys
import logging
import subprocess
from pathlib import Path

from typing import TypeVar
int_opt = TypeVar('IntOpt', int, None)


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

# TODO: Mettre tous ça dans le __init__.py de idascript


class IDANotStared(Exception):
    pass


class IDA:

    def __init__(self, binary_file, script_file, script_params=[]):
        if not Path(binary_file).exists():
            raise FileNotFoundError("Binary file: %s" % binary_file)
        if not Path(script_file).exists():
            raise FileNotFoundError("Script file: %s" % script_file)
        if script_params:
            if not isinstance(script_params, list):
                raise TypeError("script_params parameter should be a list")
        self.bin_file = Path(binary_file).absolute()
        self.script_file = Path(script_file).absolute()
        self.params = script_params.replace('"', '\\"') if script_params else []
        self._process = None

    def start(self):
        params = " "+" ".join(self.params) if self.params else ""
        cmd_line = [IDA_BINARY, '-A', '-S"%s%s"' % (self.script_file, params), self.bin_file]
        self._process = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @property
    def returncode(self):
        if self._process:
            return self._process.returncode
        else:
            raise IDANotStared()

    @property
    def terminated(self) -> bool:
        if self._process:
            if self._process.poll() is not None:
                return True
            else:
                return False
        else:
            raise IDANotStared()

    @property
    def pid(self) -> int:
        if self._process:
            return self._process.pid
        else:
            raise IDANotStared()

    def wait(self, timeout=None) -> int:
        if self._process:
            return self._process.wait(timeout)
        else:
            raise IDANotStared()

    def terminate(self) -> None:
        if self._process:
            self._process.terminate()
        else:
            raise IDANotStared()

    def kill(self) -> None:
        if self._process:
            self._process.kill()
        else:
            raise IDANotStared()

