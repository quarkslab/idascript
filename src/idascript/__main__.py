#!/usr/bin/env python3
import logging
import click
import multiprocessing
from pathlib import Path
import sys
import os
import collections
import progressbar
from typing import Optional, List, Dict

from idascript import iter_binary_files, IDA, \
                      MultiIDA, IDA_PATH_ENV, NOP_SCRIPT, get_ida_path


class FileMessage(progressbar.DynamicMessage):
    """
    Class for file messages
    """

    def __init__(self, name):
        super().__init__(name)
        self.name = name

    def __call__(self, progress, data) -> str:
        val: tuple[int,int, str] = data['dynamic_messages'][self.name]
        return ('File (%d/%d): %s' % val) if val else 'File (-/-): /'


class SuccessMessage(progressbar.Variable):
    """
    Class for success messages
    """

    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        self.name = name

    def __call__(self, progress, data) -> str:
        counter = data['dynamic_messages'][self.name]
        if counter:
            return 'OK:%d KO:%d TO:%d' % (counter['success'], counter['failure'], counter['timeout'])
        else:
            return 'OK:- KO:- TO:-'


def path_main(path: Path, script: Optional[str|Path], params: List[str], worker: int, timeout: float,
              log: Optional[str] = None, exit_venv: bool = False) -> None:
    """
    Execute the IDA script on a bunch of binaries inside a directory

    :param path: directory that contains binaries
    :param script: IDA script to launch
    :param params: script parameters
    :param worker: number of workers
    :param timeout: timeout
    :param log: log file path
    :param exit_venv: run IDA outside of the venv
    :return: None
    """

    generator = iter_binary_files(path)
    logging.debug("Counting files to analyse..")
    total = sum(1 for _ in iter_binary_files(path))

    bar = progressbar.ProgressBar(widgets=['[', FileMessage("binary"), ']',
                                           ' [', SuccessMessage("success"), '] ',
                                           '[', progressbar.Timer(), '] ',
                                           progressbar.Bar(),
                                           ' (', progressbar.AdaptiveETA(), ')',
                                           ], max_value=total)

    counter = collections.Counter({'success': 0, 'failure': 0, 'timeout': 0})
    results: Dict = {}

    i = 1
    for retcode, file in MultiIDA.map(generator, script, params, worker, timeout, exit_venv):
        if retcode == 0:
            counter['success'] += 1
        elif retcode == IDA.TIMEOUT_RETURNCODE:
            counter['timeout'] += 1
        else:
            counter['failure'] += 1

        if log is not None:
            results[file] = retcode

        size = len(file.name)
        name = file.name[:18]+".." if size > 20 else file.name+(" "*(20-size))
        bar.update(i, binary=(i, total, name), success=counter)
        i += 1

    if log is not None:
        with open(log, "w") as out:
            for file, return_code in results.items():
                result = {0: 'OK', -1: 'TO'}.get(return_code, 'KO')
                out.write(f'{file.resolve()},{result}\n')

        logging.info(f"\nLog file written in {log}")


def file_main(file: Path, script: Optional[str|Path], params: List[str], timeout: float, exit_venv: bool) -> None:
    """
    Execute the IDA script on a binary

    :param file: path to the binary file
    :param script: IDA script to launch
    :param params: script parameters
    :param timeout: timeout
    :param exit_venv: run IDA outside of the venv
    :return: None
    """

    ida = IDA(file, script, params, timeout, exit_venv)

    ida.start()
    res = ida.wait()
    sys.exit(res)


@click.command()
@click.option('-i', '--ida-path',
              type=click.Path(exists=True, path_type=Path),
              default=None,
              help="IDA Pro executable path")
@click.option('-w', '--worker',
              type=click.IntRange(1, multiprocessing.cpu_count(), clamp=True),
              default=1,
              help="Number of parallel workers (thread)")
@click.option('-s', '--script',
              type=click.Path(exists=True, path_type=Path),
              metavar="<ida script>",
              help="IDAPython script")
@click.option('-t', '--timeout',
              type=click.FloatRange(-1, clamp=False),
              help="Timeout (-1 means no timeout)",
              default=None)
@click.option('-l', '--log-file',
              type=click.Path(file_okay=True),
              default=None,
              help="Log file tow write results")
@click.option("--exit-venv",
              is_flag=True,
              default=False,
              type=bool,
              help="Run IDA outside of current virtualenv")
@click.option("-v", "--verbose",
              is_flag=True,
              default=False,
              type=bool,
              help="Enable debug logs")
@click.argument("file",
                type=click.Path(exists=True, path_type=Path),
                metavar="<file|path>")
@click.argument('params',
                nargs=-1)
def main(ida_path: Path,
         worker: int,
         script: Optional[Path],
         timeout: float,
         log_file: str,
         exit_venv: bool,
         verbose: bool,
         file: Path,
         params) -> None:
    """

    <file/path>  Binary file to analyse (or directory)\r\n
    [PARAMS]     Params meant to be sent to the script
    """

    # Configure logging
    logging.basicConfig(format="%(message)s", level=logging.DEBUG if verbose else logging.INFO)

    if ida_path:
        os.environ[IDA_PATH_ENV] = str(Path(ida_path).absolute())
    p = Path(file)

    ida_path = get_ida_path()
    if not ida_path:
        click.echo("IDA Pro executable not found, please set the IDA_PATH environment variable or use the -i option", err=True)
        sys.exit(1)
    if not ida_path.is_file():
        click.echo(f"IDA Pro path should be the executable, not the directory", err=True)
        sys.exit(1)

    if not script:
        logging.info("No script provided, just perform disassembly")
        script_to_launch: Path  = NOP_SCRIPT
        # Retrieve the nop_script to just generate IDA DB
    else:
        script_to_launch = Path(script).absolute()

    if p.is_file():
        file_main(p, script_to_launch, list(params), timeout, exit_venv)
    elif p.is_dir():
        path_main(p, script_to_launch, list(params), worker, timeout, log_file, exit_venv)
    else:
        raise FileExistsError("Invalid file type")


if __name__ == "__main__":
    main()
