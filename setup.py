#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Installation and deployment script."""

from __future__ import print_function

import glob
import os
import sys

try:
  from setuptools import find_packages, setup
except ImportError:
  from distutils.core import find_packages, setup

try:
  from distutils.command.bdist_msi import bdist_msi
except ImportError:
  bdist_msi = None

try:
  from distutils.command.bdist_rpm import bdist_rpm
except ImportError:
  bdist_rpm = None

version_tuple = (sys.version_info[0], sys.version_info[1])
if version_tuple < (3, 5):
  print((
      'Unsupported Python version: {0:s}, version 3.5 or higher '
      'required.').format(sys.version))
  sys.exit(1)

# Change PYTHONPATH to include dfvfs-snippets so that we can get the version.
sys.path.insert(0, '.')

import dfvfs-snippets  # pylint: disable=wrong-import-position


if not bdist_msi:
  BdistMSICommand = None
else:
  class BdistMSICommand(bdist_msi):
    """Custom handler for the bdist_msi command."""

    def run(self):
      """Builds an MSI."""
      # Command bdist_msi does not support the library version, neither a date
      # as a version but if we suffix it with .1 everything is fine.
      self.distribution.metadata.version += '.1'

      bdist_msi.run(self)


if not bdist_rpm:
  BdistRPMCommand = None
else:
  class BdistRPMCommand(bdist_rpm):
    """Custom handler for the bdist_rpm command."""

    def _make_spec_file(self):
      """Generates the text of an RPM spec file.

      Returns:
        list[str]: lines of the RPM spec file.
      """
      # Note that bdist_rpm can be an old style class.
      if issubclass(BdistRPMCommand, object):
        spec_file = super(BdistRPMCommand, self)._make_spec_file()
      else:
        spec_file = bdist_rpm._make_spec_file(self)

      python_package = 'python3'

      description = []
      requires = ''
      summary = ''
      in_description = False

      python_spec_file = []
      for line in iter(spec_file):
        if line.startswith('Summary: '):
          summary = line[9:]

        elif line.startswith('BuildRequires: '):
          line = 'BuildRequires: {0:s}-setuptools, {0:s}-devel'.format(
              python_package)

        elif line.startswith('Requires: '):
          requires = line[10:]
          continue

        elif line.startswith('%description'):
          in_description = True

        elif line.startswith('python setup.py build'):
          if python_package == 'python3':
            line = '%py3_build'
          else:
            line = '%py2_build'

        elif line.startswith('python setup.py install'):
          if python_package == 'python3':
            line = '%py3_install'
          else:
            line = '%py2_install'

        elif line.startswith('%files'):
          lines = [
              '%files -n {0:s}-%{{name}}'.format(python_package),
              '%defattr(644,root,root,755)',
              '%license LICENSE',
              '%doc ']

          lines.extend([
              '%{python3_sitelib}/dfvfs-snippets/*.py',
              '%{python3_sitelib}/dfvfs-snippets*.egg-info/*',
              '',
              '%exclude %{_prefix}/share/doc/*',
              '%exclude %{python3_sitelib}/dfvfs-snippets/__pycache__/*',
              '%exclude %{_bindir}/*.py'])

          python_spec_file.extend(lines)
          break

        elif line.startswith('%prep'):
          in_description = False

          python_spec_file.append(
              '%package -n {0:s}-%{{name}}'.format(python_package))
          python_summary = 'Python 3 module of {0:s}'.format(summary)

          if requires:
            python_spec_file.append('Requires: {0:s}'.format(requires))

          python_spec_file.extend([
              'Summary: {0:s}'.format(python_summary),
              '',
              '%description -n {0:s}-%{{name}}'.format(python_package)])

          python_spec_file.extend(description)

        elif in_description:
          # Ignore leading white lines in the description.
          if not description and not line:
            continue

          description.append(line)

        python_spec_file.append(line)

      return python_spec_file


dfvfs-snippets_description = (
    'Collection of example scripts that use dfVFS')

dfvfs-snippets_long_description = (
    'Collection of example scripts that use dfVFS')

setup(
    name='dfvfs-snippets',
    version=dfvfs-snippets.__version__,
    description=dfvfs-snippets_description,
    long_description=dfvfs-snippets_long_description,
    license='Apache License, Version 2.0',
    url='https://github.com/open-source-dfir/dfvfs-snippets',
    maintainer='Open Source DFIR maintainers',
    maintainer_email='open-source-dfir-maintainers@googlegroups.com',
    cmdclass={
        'bdist_msi': BdistMSICommand,
        'bdist_rpm': BdistRPMCommand},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    packages=find_packages('.', exclude=[
        'scripts', 'tests', 'tests.*', 'utils']),
    package_dir={
        'dfvfs-snippets': 'dfvfs-snippets'
    },
    scripts=glob.glob(os.path.join('scripts', '[a-z]*.py')),
    data_files=[
        ('share/doc/dfvfs-snippets', [
            'LICENSE']),
    ],
)
