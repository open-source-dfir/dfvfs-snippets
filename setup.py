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
if version_tuple[0] not in (2, 3):
  print('Unsupported Python version: {0:s}.'.format(sys.version))
  sys.exit(1)

elif version_tuple[0] == 2 and version_tuple < (2, 7):
  print((
      'Unsupported Python 2 version: {0:s}, version 2.7 or higher '
      'required.').format(sys.version))
  sys.exit(1)

elif version_tuple[0] == 3 and version_tuple < (3, 4):
  print((
      'Unsupported Python 3 version: {0:s}, version 3.4 or higher '
      'required.').format(sys.version))
  sys.exit(1)


setup(
    name='dfvfs-snippets',
    version='20191123',
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
