
from setuptools import setup


with open("README.md") as f:
    README = f.read()


setup(
    name='idascript',
    version='0.1.0',
    description='IDA Pro wrapper to launch script on binaries',
    author='Robin David',
    author_email='rdavid@quarkslab.com',
    url='https://github.com/quarkslab/idascript',
    long_description_content_type='text/markdown',
    long_description=README,
    project_urls={
        "Documentation": "https://quarkslab.github.io/diffing-portal/idascript/README.html",
        "Bug Tracker": "https://github.com/quarkslab/idascript/issues",
        "Source": "https://github.com/quarkslab/idascript"
    },
    packages=['idascript'],
    install_requires=[
        'python-magic',
        'click',
        'progressbar2'
    ],
    license="AGPL-3.0",
    classifiers=[
        'Topic :: Security',
        'Environment :: Console',
        'Operating System :: OS Independent',
    ],
    scripts=['bins/idascripter']
)
