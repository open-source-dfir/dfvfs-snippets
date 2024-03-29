#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Installation and deployment script."""

import glob
import os
import pkg_resources
import sys

try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

try:
  from distutils.command.bdist_msi import bdist_msi
except ImportError:
  bdist_msi = None

version_tuple = (sys.version_info[0], sys.version_info[1])
if version_tuple < (3, 6):
  print((
      'Unsupported Python version: {0:s}, version 3.6 or higher '
      'required.').format(sys.version))
  sys.exit(1)


if not bdist_msi:
  BdistMSICommand = None
else:
  class BdistMSICommand(bdist_msi):
    """Custom handler for the bdist_msi command."""

    # pylint: disable=invalid-name
    def run(self):
      """Builds an MSI."""
      # Command bdist_msi does not support the library version, neither a date
      # as a version but if we suffix it with .1 everything is fine.
      self.distribution.metadata.version += '.1'

      bdist_msi.run(self)


def parse_requirements_from_file(path):
  """Parses requirements from a requirements file.

  Args:
    path (str): path to the requirements file.

  Yields:
    str: name and optional version information of the required package.
  """
  with open(path, 'r') as file_object:
    file_contents = file_object.read()

  for requirement in pkg_resources.parse_requirements(file_contents):
    try:
      name = str(requirement.req)
    except AttributeError:
      name = str(requirement)

    if name.startswith('pip '):
      continue

    yield name


setup(
    name='dfvfs-snippets',
    version='20201020',
    description='Collection of example scripts that use dfVFS',
    long_description='Collection of example scripts that use dfVFS',
    license='Apache License, Version 2.0',
    url='https://github.com/open-source-dfir/dfvfs-snippets',
    maintainer='Open Source DFIR maintainers',
    maintainer_email='open-source-dfir-maintainers@googlegroups.com',
    cmdclass={
        'bdist_msi': BdistMSICommand},
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
    install_requires=parse_requirements_from_file('requirements.txt'),
    tests_require=parse_requirements_from_file('test_requirements.txt'),
)
