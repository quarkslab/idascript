
from setuptools import setup

setup(
    name='idascript',
    version='0.1',
    description='IDA Pro wrapper to launch script on binaries',
    author='Robin David',
    author_email='rdavid@quarkslab.com',
    url='https://github.com/quarkslab/idascript',
    packages=['idascript'],
    install_requires=[
        'python-magic',
        'click',
        'progressbar2'
    ],
    scripts=['bins/idascripter']
)
