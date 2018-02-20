import subprocess
from idascript import IDA_BINARY
from pathlib import Path
from multiprocessing import Pool, Queue
import queue


from typing import TypeVar
int_opt = TypeVar('IntOpt', int, None)


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


class MultiIDAAlreadyRunningException(Exception):
    pass


class MultiIDA:

    _data_queue = Queue()
    _script_file = None
    _params = []
    _running = False

    @staticmethod
    def _worker_handle(bin_file):
        ida = IDA(bin_file, MultiIDA._script_file, MultiIDA._params)
        ida.start()
        res = ida.wait()
        MultiIDA._data_queue.put((res, bin_file))
        return res, bin_file.name

    @staticmethod
    def map(generator, script, params=[], workers=None):
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
