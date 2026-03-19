"""PyInstaller entry point wrapper for CloudHop.

This module avoids the relative-import issue that occurs when PyInstaller
uses cloudhop/cli.py directly as a script entry point.  By importing
through the package, relative imports within cloudhop work correctly.
"""
from cloudhop.cli import main

if __name__ == '__main__':
    main()
