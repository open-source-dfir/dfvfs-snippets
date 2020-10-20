#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Installation and deployment script."""

from __future__ import print_function

import glob
import os
import sys

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup


version_tuple = (sys.version_info[0], sys.version_info[1])
if version_tuple < (3, 6):
  print((
      'Unsupported Python version: {0:s}, version 3.6 or higher '
      'required.').format(sys.version))
  sys.exit(1)


setup(
    name='dfvfs-snippets',
    version='20201020',
    description='Collection of example scripts that use dfVFS',
    long_description='Collection of example scripts that use dfVFS',
    license='Apache License, Version 2.0',
    url='https://github.com/open-source-dfir/dfvfs-snippets',
    maintainer='Open Source DFIR maintainers',
    maintainer_email='open-source-dfir-maintainers@googlegroups.com',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    scripts=glob.glob(os.path.join('scripts', '[a-z]*.py')),
    data_files=[
        ('share/doc/dfvfs-snippets', [
            'LICENSE']),
    ],
)
