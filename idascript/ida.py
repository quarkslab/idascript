import os
import sys
import logging
import subprocess
from pathlib import Path
import multiprocessing
from multiprocessing import Pool, Queue
import queue
import random
import time

from typing import TypeVar
int_opt = TypeVar('IntOpt', int, None)

#logger = multiprocessing.log_to_stderr()
#logger.setLevel(multiprocessing.SUBDEBUG)



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


def _start_ida(bin_file):
    #  Parrallelized function
    ida = IDA(bin_file, "/home/robin/Quarkslab/binexport_stuff/export_bin.py", [])
    ida.start()
    res = ida.wait()
    #queue.put((res, bin_file))
    return res, bin_file

class MultiIDA:

    def __init__(self, nproc=None):
        #  n_cpu = nproc if nproc else multiprocessing.cpu_count()
        self.pool = Pool(nproc)
        self.queue = Queue()
        self.script = None
        self.params = None

    def _start_ida(self, bin_file):
        #  Parrallelized function
        #ida = IDA(bin_file, self.script, self.params)
        #ida.start()
        #res = ida.wait()
        res = random.randint(1, 15)
        time.sleep(res)
        self.queue.put((res, bin_file))
        return res, bin_file

    def map(self, gen, script_file, params=[]):
        self.script = script_file
        self.params = params
        task = self.pool.map_async(self._start_ida, gen)
        while True:
            try:
                data = self.queue.get(True, timeout=0.5)
                if data:
                    yield data
            except queue.Empty:
                pass

            if task.ready():
                break

    def map_async(self, gen, script_file, params):
        pass




def main_multi():
    files = [
        "VirusShare_00a0feb5311a21e27c608c146411dd8c", "VirusShare_0a1c9357dcc23b57209b3d5be17ba998",
        "VirusShare_00a1d1ee672132c34d5a905061e0f718", "VirusShare_0a2b4528fe9770070f0e30f729b70acd",
        "VirusShare_00a4b2373c44db998407f69cb46e19d0", "VirusShare_0a2e1377a66bdd8dffe2a8cab0191dac",
        "VirusShare_0a03acdbf702cfb5e06945ae9d10f140", "VirusShare_0a2e711a489b06b563d97ab7fe2ef362",
        "VirusShare_0a03be9ce24a10edcd6e8e67c3312576", "VirusShare_0a2f514913b234ee35d3906008e348f9",
        "VirusShare_0a0aefc6403719f5cfead05cbd93d0c1", "VirusShare_0a2fa30b369103d66ec2b50888627e45",
        "VirusShare_0a0b708cc87c53fb8adbc6a8177a2672", "VirusShare_0a2fbf2a2089e5596f75e33be84a6639",
        "VirusShare_0a0d21ca90ac7f7975c26f8d40259e0a", "VirusShare_0a2ffe2ed07d7b51a2524ea9c2a87767",
        "VirusShare_0a0f6591b1ef4e281ca6b2b4e0fa776a", "VirusShare_0a3d324d71b99d5ebc6a1e6a0acdc12d",
        "VirusShare_0a1a79bcd6e1c5e17ddc7ec8928621af", "VirusShare_0a3f63f735344b4b834e3b0d85c18111",
        "VirusShare_0a1ab04035e0bb85e11d4b8d394f015d", "VirusShare_0a4a9634423d27d148ae487ab44c8c4a",
        "VirusShare_0a1c135e26f64fdde3e030476dfdf5ca", "VirusShare_0a4b5285828389b8e956ae4d8c5c0dfb"]
    gen = map(lambda x: "/home/robin/Quarkslab/binexport_stuff/sampling/" + x, files)
    script_file = "/home/robin/Quarkslab/binexport_stuff/export_bin.py"
    ida = MultiIDA()
    for r, f in ida.map(gen, script_file):
        print("INTOOTOTOTO")
        print(r, f)
    print("DONE")

def main_single():
    bin_file = "/home/robin/Quarkslab/binexport_stuff/sampling/VirusShare_0a1c135e26f64fdde3e030476dfdf5ca"
    script_file = "/home/robin/Quarkslab/binexport_stuff/export_bin.py"
    ida = IDA(bin_file, script_file)
    ida.start()
    print(ida.wait())

if __name__ == "__main__":
    main_multi()
