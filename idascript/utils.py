from pathlib import Path
import magic

BINARY_FORMAT = {'application/x-dosexec',
                 'application/x-sharedlib',
                 'application/x-mach-binary',
                 'application/x-executable'}


def iter_binary_files(path):
    p = Path(path)
    if p.is_file():
        if magic.from_file(str(p), mime=True) in BINARY_FORMAT:
            yield p
    elif p.is_dir():
        for child in p.iterdir():
            yield from iter_binary_files(child)
