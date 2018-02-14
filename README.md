# Idascript

Idascript is a python library allowing to launch IDA Python script on binary files via the command line.
Among other things it allows to serialize and to transmit simple data to caller in order to retrieve them
in the main script.

# Installation

Installing the library can be done with:

    git clone gitlab@gitlab.qb:rdavid/idascript.git
    cd idascript
    python3 setup.py install

After installation `idascript` should be ready for import and the binary `idascripter.py`
should be in the path to use the library as a program.

# Program usage

After installation the script `idascripter.py` is available in the path. It helps
quickly and simply to execute a given idapython script on all the executables of a
given directory. 

TODO

> Disclaimer: You should make sure that the import of your script are satisfied (in python2) before
luanching it against binaries

# Library usage

TODO