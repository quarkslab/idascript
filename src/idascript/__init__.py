import sys
import os
from pathlib import Path
import logging

from idascript.ida import IDA, MultiIDA, TIMEOUT_RETURNCODE, IDA_PATH_ENV, get_ida_path
from idascript.utils import iter_binary_files


NOP_SCRIPT = (Path(__file__).parent / 'nop_script.py').absolute()


def is_headless() -> bool:
    import psutil
    current_process = psutil.Process()
    process_name = current_process.name()
    return process_name.startswith("idat")
