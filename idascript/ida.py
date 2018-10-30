import subprocess
from idascript import IDA_BINARY
from pathlib import Path
from multiprocessing import Pool, Queue
import queue
from typing import List, Optional, Iterable, Union, Generator, Tuple


class IDANotStared(Exception):
    """
    This exception is raised when attempting
    to call a function of the `IDA` class before
    having called `start`.
    """
    pass


class IDA:
    """
    Class representing an IDA execution on a given file
    with the given script. This class is a wrapper for
    subprocess on IDA.
    """

    def __init__(self, binary_file: str, script_file: str, script_params: List[str]=[]):
        """
        Constructor for IDA object.

        :param binary_file: path of the binary file to analyse
        :param script_file: path to the script to execute on the binary file
        :param script_params: additional parameters sent to the script (available via idc.ARGV in idapython)
        """
        if not Path(binary_file).exists():
            raise FileNotFoundError("Binary file: %s" % binary_file)
        if not Path(script_file).exists():
            raise FileNotFoundError("Script file: %s" % script_file)
        if script_params:
            if not isinstance(script_params, list):
                raise TypeError("script_params parameter should be a list")
        self.bin_file = Path(binary_file).resolve()
        self.script_file = Path(script_file).resolve()
        self.params = [x.replace('"', '\\"') for x in script_params] if script_params else []
        self._process = None

    def start(self) -> None:
        """
        Start the IDA process on the binary.
        :return: None
        """

        params = " "+" ".join(self.params) if self.params else ""
        cmd_line = [IDA_BINARY.as_posix(), '-A', '-S%s%s' % (self.script_file.as_posix(), params), self.bin_file.as_posix()]

        self._process = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @property
    def returncode(self) -> Optional[int]:
        """
        Get the returncode of the process. Raise IDANotStart
        if called before launching the process.
        :return: return code or None
        """
        if self._process:
            return self._process.returncode
        else:
            raise IDANotStared()

    @property
    def terminated(self) -> bool:
        """
        Boolean function returning True if the process is terminated
        :return: bool of Wether or not the process is terminated
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

    def wait(self, timeout: int=None) -> int:
        """
        Wait for the process to finish. This function hangs until
        the process terminate. A timeout can be given which raises
        TimeoutExpired if the timeout is exceeded (subprocess mechanism).
        :param timeout: int value
        :return: return code
        """
        if self._process:
            return self._process.wait(timeout)
        else:
            raise IDANotStared()

    def terminate(self) -> None:
        """
        Call terminate on the IDA process (kill -15)
        :return: None
        """
        if self._process:
            self._process.terminate()
        else:
            raise IDANotStared()

    def kill(self) -> None:
        """
        Call kill on the IDA subprocess (kill -9)
        :return: None
        """
        if self._process:
            self._process.kill()
        else:
            raise IDANotStared()


class MultiIDAAlreadyRunningException(Exception):
    """
    Exception raised if the `map` function of MultiIDA
    is called while another map operation is still pending.
    Design choices disallow launching two MultiIDA.map
    function in the same time.
    """
    pass


class MultiIDA:
    """
    Class to trigger multiple IDA processes concurrently
    on a bunch of files.
    """

    _data_queue = Queue()
    _script_file = None
    _params = []
    _running = False

    @staticmethod
    def _worker_handle(bin_file):
        """Worker function run concurrently"""
        ida = IDA(bin_file, MultiIDA._script_file, MultiIDA._params)
        ida.start()
        res = ida.wait()
        MultiIDA._data_queue.put((res, bin_file))
        return res, bin_file.name

    @staticmethod
    def map(generator: Iterable[Path], script: Union[str, Path], params: List[str]=[], workers: int=None)\
            -> Generator[Tuple[int, Path], None, None]:
        """
        Iterator the generator sent and apply the script file on each
        files concurrently on a bunch of IDA workers. The function consume
        the generator as fast as it can occupy all the workers and yield a
        tuple (return code, path file) everytime an IDA process as terminated.
        :param generator: Iterable of file paths strings (or Path)
        :param script: path to the script to execute
        :param params: list of parameters to send to the script
        :param workers: number of workers to trigger in parallel
        :return: generator of files processed (return code, file path)
        """
        if MultiIDA._running:
            raise MultiIDAAlreadyRunningException()
        MultiIDA._running = True
        MultiIDA._script_file = script
        MultiIDA._params = params
        pool = Pool(workers)
        task = pool.map_async(MultiIDA._worker_handle, generator)
        while True:
            try:
                data = MultiIDA._data_queue.get(True, timeout=0.5)
                if data:
                    yield data
            except queue.Empty:
                pass
            if task.ready():
                break
        MultiIDA._running = False
