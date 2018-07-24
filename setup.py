#!/usr/bin/env python3

from os import path

from setuptools import setup, find_packages

import keyper

def run_setup():
    """Run package setup."""
    here = path.abspath(path.dirname(__file__))

    # Get the long description from the README file
    try:
        with open(path.join(here, 'README.md')) as f:
            long_description = f.read()
    except:
        # This happens when running tests
        long_description = None

    setup(
        name='keyper',
        version=keyper.__version__,
        description='A utility for dealing with the macOS keychain.',
        long_description=long_description,
        url='https://github.com/Microsoft/keyper',
        author='Dale Myers',
        author_email='dalemy@microsoft.com',
        license='MIT',
        install_requires=[],
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Console',
            'Environment :: MacOS X',
            'Intended Audience :: Developers',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.7',
            'Topic :: Software Development',
            'Topic :: Utilities'
        ],

        keywords='apple, macOS, keychain, certificates, passwords',
        packages=find_packages(exclude=['docs', 'tests'])
    )

if __name__ == "__main__":
    run_setup()
