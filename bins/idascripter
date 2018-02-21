#!/usr/bin/env python3
import click
import multiprocessing
from pathlib import Path
import sys
import os
import progressbar
import tempfile


class FileMessage(progressbar.DynamicMessage):
    def __init__(self, name):
        self.name = name

    def __call__(self, progress, data):
        val = data['dynamic_messages'][self.name]
        return 'File (%d/%d): %s' % val if val else 'File (-/-): /'


class SuccessMessage(progressbar.DynamicMessage):
    def __init__(self, name):
        self.name = name

    def __call__(self, progress, data):
        val = data['dynamic_messages'][self.name]
        return 'OK:%d KO:%d' % val if val else 'OK:- KO:-'


def path_main(path, script, params, worker):
    from idascript import MultiIDA, iter_binary_files
    generator = iter_binary_files(path)
    print("Counting files to analyse..")
    total = sum(1 for _ in iter_binary_files(path))
    bar = progressbar.ProgressBar(widgets=['[', FileMessage("binary"), ']',
                                           ' [', SuccessMessage("success"), '] ',
                                           '[', progressbar.Timer(), '] ',
                                           progressbar.Bar(),
                                           ' (', progressbar.AdaptiveETA(), ')',
                                           ], max_value=total)
    success = 0
    failure = 0
    failure_files = []
    i = 1
    for retcode, file in MultiIDA.map(generator, script, params, worker):
        if retcode == 0:
            success += 1
        else:
            failure += 1
            failure_files.append(str(file))
        size = len(file.name)
        name = file.name[:18]+".." if size > 20 else file.name+(" "*(20-size))
        bar.update(i, binary=(i, total, name), success=(success, failure))
        i += 1

    if failure:
        f = tempfile.mktemp(prefix="idascripter")
        with open(f, "wb") as out:
            for b in failure_files:
                out.write('%s\n' % b)
        print("Fail")


def file_main(file, script, params):
    from idascript import IDA
    ida = IDA(file, script, params)
    ida.start()
    res = ida.wait()
    sys.exit(res)


@click.command()
@click.option('-i', '--ida-path', type=click.Path(exists=True), default=None, help="IDA Pro installation directory")
@click.option('-w', '--worker', type=click.IntRange(1, multiprocessing.cpu_count(), clamp=True), default=None,
              help="Number of parrallel workers (thread)")
@click.argument("file", type=click.Path(exists=True), metavar="<file|path>")
@click.argument('script', type=click.Path(exists=True), metavar="<ida script>")
@click.argument('params', nargs=-1)
def main(ida_path, worker, file, script, params):
    """
    <file/path>  Binary file to analyse (or directory)\r\n
    <script>     Path to idapython script to execute\r\n
    [PARAMS]     Params meant to be sent to idapython script
    """
    if ida_path:
        os.environ['IDA_PATH'] = str(Path(ida_path).absolute())
    p = Path(file)
    if p.is_file():
        file_main(p, script, list(params))
    elif p.is_dir():
        path_main(p, script, list(params), worker)
    else:
        raise FileExistsError("Invalid file type")


if __name__ == "__main__":
    main()
