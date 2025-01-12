from pathlib import Path
import magic
from typing import Generator, Union

BINARY_FORMAT = {'application/x-dosexec',
                 'application/x-sharedlib',
                 'application/x-mach-binary',
                 'application/x-executable',
                 'application/x-pie-executable'}

EXTENSIONS_WHITELIST = {'application/octet-stream': ['.dex']}


def iter_binary_files(path: Union[str, Path]) -> Generator[Path, None, None]:
    """
    Iterate a given directory looking for all the binary executable
    files avec the magic mime type: x-doxexec, x-sharedlib, x-mach-binary
    and x-executable.

    :param path: Path where to start looking for binary files
    :type path: Union[str, Path]
    :return: Generator of binary file paths
    :rtype: Generator[Path]
    """

    p = Path(path)
    if p.is_file() and not p.is_symlink():
        mime_type = magic.from_file(str(p), mime=True)
        if mime_type in BINARY_FORMAT:
            yield p
        elif p.suffix in EXTENSIONS_WHITELIST.get(mime_type, []):
            yield p
    elif p.is_dir() and not p.is_symlink():
        for child in p.iterdir():
            yield from iter_binary_files(child)
