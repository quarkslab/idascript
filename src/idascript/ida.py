import enum
import subprocess
import logging
import sys
from pathlib import Path
from multiprocessing import Pool, Queue, Manager
import queue
import os
import shutil
from typing import List, Optional, Iterable, Union, Generator, TYPE_CHECKING

import io

OptPath = Optional[Path]
OptPathLike = Optional[Union[Path, str]]


IDA_PATH_ENV = "IDA_PATH"

NOP_SCRIPT = (Path(__file__).parent / 'nop_script.py').absolute()


def __get_names() -> list[str]:
    names = ["idat64", "idat"]
    if sys.platform == "win32":
        return [x+".exe" for x in names]
    else:
        return names


def get_ida_path() -> Path | None:
    """
    Get the path to the IDA Pro executable.
    If IDA_PATH environment variable is set, it will use that.
    It can be either the path to the executable or the directory containing it.
    Otherwise, it will search in the PATH environment variable.
    If not found, it will return None.

    :return: Path to the IDA Pro executable or None if not found
    """
    # First search in ENV variables
    if ida_path := os.environ.get(IDA_PATH_ENV):
        # Return the path as-is
        ida_path = Path(ida_path)
        
        if not ida_path.exists():
            logging.warning(f"IDA_PATH environment variable set to {ida_path}, but it does not exist.")
            return None
        elif ida_path.is_file() or ida_path.is_symlink():
            return ida_path.resolve()
        elif ida_path.is_dir():
            # Check for the binary in the directory
            for bin_name in __get_names():
                candidate = ida_path / bin_name
                if candidate.exists() and candidate.is_file():
                    logging.debug(f"Use IDA Pro from IDA_PATH env variable: {candidate}")
                    return candidate.resolve()
            # if not found fallback to None
        else:
            assert False, "Invalid file type for IDA_PATH env variable"
    else:
        for bin_name in __get_names():
            if ida_path := shutil.which(bin_name):  # Search for it in the $PATH
                ida_path = Path(ida_path)
                logging.debug(f"Use IDA Pro found in PATH: {ida_path}")
                return ida_path.resolve()

    logging.warning("IDA Pro executable not found in $PATH or IDA_PATH env variable")
    return None


class IDAException(Exception):
    """
    Base class for exceptions in the IDA module.
    """

    pass


class IDANotStared(IDAException):
    """
    This exception is raised when attempting
    to call a function of the `IDA` class before
    having called `start`.
    """

    pass


class IDAModeNotSet(IDAException):
    """
    This exception is raised when the IDA Mode has not been set before calling `start`.
    """

    pass


class MultiIDAAlreadyRunning(IDAException):
    """
    Exception raised if the `map` function of MultiIDA
    is called while another map operation is still pending.
    Design choices disallow launching two MultiIDA.map
    function in the same time.
    """

    pass


class IDAMode(enum.Enum):
    """
    Different modes possible for the IDA class
    """

    # Default value
    NOTSET = enum.auto()

    # Used when IDA will be launched for an IDAPython script
    # It will preprend -S[script.py] on the command line
    IDAPYTHON = enum.auto()

    # Used when IDA will be launched directly with options
    # It will preprend -O[option] to every options provided
    DIRECT = enum.auto()


class IDA:
    """
    Class representing an IDA execution on a given file
    with a given script. This class is a wrapper to
    subprocess IDA.
    """

    TIMEOUT_RETURNCODE: int = 0x1001 # arbitrary value

    def __init__(self,
                 binary_file: Union[Path, str],
                 script_file: OptPathLike = NOP_SCRIPT,
                 script_params: Optional[List[str]] = None,
                 timeout: Optional[float] = None,
                 exit_virtualenv: bool = False,
                 database_path: Optional[Union[Path, str]] = None):
        """
        :param binary_file: path of the binary file to analyse
        :param script_file: path to the Python script to execute on the binary (if required).
                            By default the NOP_SCRIPT is used, that will quit after terminating the analysis.
                            If you want to avoid using a script at all, set this parameter to None.
        :param script_params: additional parameters to send either to the script or IDA directly
        :param exit_virtualenv: exit current virtual env before calling IDA
        :param database_path: specify the output database (implies deleting the old pre-existing database, if any)
        """

        if not Path(binary_file).exists():
            raise FileNotFoundError(f"Binary file: {binary_file}")

        self.bin_file: Path = Path(binary_file).resolve()  #: File to the binary
        self._process = None

        self.script_file: OptPath = None  #: script file to execute
        self.params: List[str] = []  #: list of paramaters given to IDA

        self.timeout: Optional[float] = None
        if timeout is not None:
            if timeout > 0:
                self.timeout = timeout
        self.exit_virtualenv: bool = exit_virtualenv
        self._database_path: Optional[Path] = Path(database_path) if database_path else None
        self._stdout_buf: Optional[io.BytesIO] = None
        self._stderr_buf: Optional[io.BytesIO] = None

        if script_file is not None:  # Mode IDAPython
            self._set_idapython(script_file, script_params)
        else:  # Direct mode
            self._set_direct(script_params)

    def _set_idapython(self, script_file: OptPathLike, script_params: List[str]|None = None) -> None:
        """
        Set IDAPython script parameter.

        :param script_file: path to the script to execute on the binary file
        :param script_params: additional parameters sent to the script (available via idc.ARGV in idapython)
        """
        # Configure script file
        if script_file is None:
            raise FileNotFoundError("In IDAPython mode, script_file must be set")
        else:
            self.script_file = Path(script_file).resolve()
            if not Path(script_file).exists():
                raise FileNotFoundError(f"Script file: {script_file}")

        # Configure script parameters
        if script_params is None:
            script_params = []
        self.params = [x.replace('"', '\\"') for x in script_params] if script_params else []

        self.mode = IDAMode.IDAPYTHON

    def _set_direct(self, script_options: List[str]|None) -> None:
        """
        Set parameters script in direct mode

        :param script_options: List of script options
        :return: None
        """
        if script_options:
            for option in script_options:
                if ':' not in option:
                    raise TypeError('Options must have a ":"')
                self.params.append(f'-O{option}')
        else:
            logging.warning(f"Direct mode used without any options.")

        self.mode = IDAMode.DIRECT

    def start(self) -> None:
        """
        Start the IDA process on the binary.
        """
        ida_path = get_ida_path()
        if ida_path is None:
            raise IDAException("IDA Pro executable not found. Please set the IDA_PATH "
                               "environment variable or ensure it is in your PATH.")

        cmd_line = [ida_path.as_posix(), '-A']

        if self._database_path:
            cmd_line.append(f"-o{self._database_path.as_posix()}")

        if self.mode == IDAMode.IDAPYTHON:
            assert self.script_file is not None, "Script file must be set for IDAPython mode"
            params = " "+" ".join(self.params) if self.params else ""
            cmd_line.append('-S%s%s' % (self.script_file.as_posix(), params))
        elif self.mode == IDAMode.DIRECT:
            cmd_line.extend(self.params)
        else:
            raise

        cmd_line.append(self.bin_file.as_posix())
        logging.debug(f"run: {' '.join(cmd_line)}")

        env = os.environ
        env["TVHEADLESS"] = "1"
        env["TERM"] = "xterm"
        if self.exit_virtualenv:
            venv = env.pop("VIRTUAL_ENV", None)
            if venv:
                paths = env["PATH"].split(":")
                env["PATH"] = ":".join(x for x in paths if venv not in x)

        self._process = subprocess.Popen(
            cmd_line,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # See `https://www.hex-rays.com/blog/igor-tip-of-the-week-08-batch-mode-under-the-hood/`_
            env=env
        )

    @property
    def returncode(self) -> Optional[int]:
        """
        Get the returncode of the process. Raise IDANotStart
        if called before launching the process.
        """

        if self._process:
            return self._process.returncode
        else:
            raise IDANotStared()

    @property
    def terminated(self) -> bool:
        """
        Boolean function returning True if the process is terminated
        """

        if self._process:
            if self._process.poll() is not None:
                return True
            else:
                return False
        else:
            raise IDANotStared()

    @property
    def pid(self) -> int:
        """
        Returns the PID of the IDA process

        :return: int (PID of the process)
        """

        if self._process:
            return self._process.pid
        else:
            raise IDANotStared()

    def wait(self) -> int:
        """
        Wait for the process to finish and capture its output.
        Uses communicate() internally to drain stdout/stderr pipes,
        avoiding deadlocks when pipe buffers fill up.
        A timeout can be given which terminates the process if exceeded.
        After this call, stdout and stderr are available as BytesIO objects
        via the .stdout and .stderr properties.
        """

        if self._process:
            try:
                stdout_data, stderr_data = self._process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                self._process.terminate()
                stdout_data, stderr_data = self._process.communicate()
                self._stdout_buf = io.BytesIO(stdout_data or b"")
                self._stderr_buf = io.BytesIO(stderr_data or b"")
                return self.TIMEOUT_RETURNCODE
            self._stdout_buf = io.BytesIO(stdout_data or b"")
            self._stderr_buf = io.BytesIO(stderr_data or b"")
            return self._process.returncode
        else:
            raise IDANotStared()

    def terminate(self) -> None:
        """
        Call terminate on the IDA process (kill -15)
        """

        if self._process:
            self._process.terminate()
        else:
            raise IDANotStared()

    def kill(self) -> None:
        """
        Call kill on the IDA subprocess (kill -9)
        """

        if self._process:
            self._process.kill()
        else:
            raise IDANotStared()

    @property
    def stdout(self) -> io.BufferedIOBase:
        """
        Process stdout. Before wait(), returns the raw pipe.
        After wait(), returns a BytesIO of the captured output.
        """

        if self._process:
            if self._stdout_buf is not None:
                return self._stdout_buf
            return self._process.stdout
        else:
            raise IDANotStared()

    @property
    def stderr(self) -> io.BufferedIOBase:
        """
        Process stderr. Before wait(), returns the raw pipe.
        After wait(), returns a BytesIO of the captured output.
        """

        if self._process:
            if self._stderr_buf is not None:
                return self._stderr_buf
            return self._process.stderr
        else:
            raise IDANotStared()


class MultiIDA:
    """
    Class to trigger multiple IDA processes concurrently
    on a bunch of files.
    """

    @staticmethod
    def _worker(ingress: Queue, egress: Queue, script_file: OptPathLike,
                params: list[str]|None, timeout: float, exit_virtualenv: bool) -> None:
        while True:
            try:
                file = ingress.get(timeout=0.5)

                ida = IDA(file, script_file, params, timeout, exit_virtualenv)
                ida.start()
                res = ida.wait()

                egress.put((file, res))
            except queue.Empty:
                pass
            except KeyboardInterrupt:
                break

    @staticmethod
    def map(generator: Iterable[Path],
            script: OptPathLike = None,
            params: List[str]|None = None,
            workers: int = 4,
            timeout: Optional[float] = None,
            exit_virtualenv: bool = False) -> Generator[tuple[int, Path], None, None]:
        """
        Iterator the generator sent and apply the script file on each
        file concurrently on a bunch of IDA workers. The function consume
        the generator as fast as it can occupy all the workers and yield a
        tuple (return code, path file) everytime an IDA process as terminated.

        :param generator: Iterable of file paths strings (or Path)
        :param script: path to the script to execute
        :param params: list of parameters to send to the script
        :param workers: number of workers to trigger in parallel
        :param timeout: timeout for IDA runs (-1 means infinity)
        :param exit_virtualenv: exit current virtualenv before calling IDA
        :return: generator of files processed (return code, file path)
        """

        manager = Manager()
        ingress = manager.Queue()
        egress = manager.Queue()
        pool = Pool(workers)

        # Launch all workers
        for i in range(workers):
            pool.apply_async(MultiIDA._worker, (ingress, egress, script, params, timeout, exit_virtualenv))

        # Pre-fill ingress queue
        total = 0
        for file in generator:
            ingress.put(file)
            total += 1

        if not total:
            logging.warning("no file provided found in the iterator")
            pool.terminate()
            return

        i = 0
        while True:
            path, res = egress.get()
            i += 1
            yield res, path

            # once all items have been processed
            if i == total:
                break

        pool.terminate()
