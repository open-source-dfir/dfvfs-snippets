#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the recursive hasher script."""

from __future__ import unicode_literals

import io
import os
import sys
import unittest

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.resolver import resolver
from dfvfs.path import factory as path_spec_factory

from scripts import recursive_hasher

from tests import test_lib


class TestOutputWriter(recursive_hasher.OutputWriter):
  """Output writer for testing the recursive hasher script.

  Attributes:
    hashes (list[tuple[str, str]]): paths and their corresponding hash value.
  """

  def __init__(self, encoding='utf-8'):
    """Initializes an output writer.

    Args:
      encoding (Optional[str]): input encoding.
    """
    super(TestOutputWriter, self).__init__(encoding=encoding)
    self.hashes = []

  def Close(self):
    """Closes the output writer object."""
    return

  def Open(self):
    """Opens the output writer object."""
    return

  def WriteFileHash(self, path, hash_value):
    """Writes the file path and hash.

    Args:
      path (str): path of the file.
      hash_value (str): message digest hash calculated over the file data.
    """
    self.hashes.append((path, hash_value))


@test_lib.skipUnlessHasTestFile(['image.qcow2'])
class RecursiveHasherTest(test_lib.BaseTestCase):
  """Tests for the recursive hasher."""

  # pylint: disable=protected-access

  def testCalculateHashDataStream(self):
    """Tests the _CalculateHashDataStream function."""
    path = self._GetTestFilePath(['image.qcow2'])
    test_hasher = recursive_hasher.RecursiveHasher()

    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_QCOW, parent=path_spec)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK, location='/passwords.txt',
        parent=path_spec)

    file_entry = resolver.Resolver.OpenFileEntry(path_spec)

    expected_digest_hash = (
        '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252')

    digest_hash = test_hasher._CalculateHashDataStream(file_entry, '')
    self.assertEqual(digest_hash, expected_digest_hash)

  def testCalculateHashesFileEntry(self):
    """Tests the _CalculateHashesFileEntry function."""
    path = self._GetTestFilePath(['image.qcow2'])
    test_hasher = recursive_hasher.RecursiveHasher()

    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_QCOW, parent=path_spec)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK, location='/passwords.txt',
        parent=path_spec)

    file_system = resolver.Resolver.OpenFileSystem(path_spec)
    file_entry = resolver.Resolver.OpenFileEntry(path_spec)

    output_writer = TestOutputWriter()
    test_hasher._CalculateHashesFileEntry(
        file_system, file_entry, [''], output_writer)

    self.assertEqual(len(output_writer.hashes), 1)

    expected_hashes = [
        ('/passwords.txt',
         '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252')]
    self.assertEqual(output_writer.hashes, expected_hashes)

  def testGetDisplayPath(self):
    """Tests the _GetDisplayPath function."""
    path = self._GetTestFilePath(['image.qcow2'])
    test_hasher = recursive_hasher.RecursiveHasher()

    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_QCOW, parent=path_spec)
    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK, location='/passwords.txt',
        parent=path_spec)

    display_path = test_hasher._GetDisplayPath(
        path_spec, ['', 'passwords.txt'], 'stream')
    self.assertEqual(display_path, '/passwords.txt:stream')

  def testCalculateHashes(self):
    """Tests the CalculateHashes function."""
    path = self._GetTestFilePath(['image.qcow2'])
    test_hasher = recursive_hasher.RecursiveHasher()

    base_path_specs = test_hasher.GetBasePathSpecs(path)
    output_writer = TestOutputWriter()
    test_hasher.CalculateHashes(base_path_specs, output_writer)

    self.assertEqual(len(output_writer.hashes), 3)

    expected_hashes = [
        ('/a_directory/another_file',
         'c7fbc0e821c0871805a99584c6a384533909f68a6bbe9a2a687d28d9f3b10c16'),
        ('/a_directory/a_file',
         '4a49638d0e1055fd9e4c17fef7fdf4d6ccf892b6d9c2f64164203c4bfb0ec92d'),
        ('/passwords.txt',
         '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252')]
    self.assertEqual(output_writer.hashes, expected_hashes)

  def testGetBasePathSpecs(self):
    """Tests the GetBasePathSpecs function."""
    path = self._GetTestFilePath(['image.qcow2'])
    test_hasher = recursive_hasher.RecursiveHasher()

    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_QCOW, parent=expected_path_spec)
    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_TSK, location='/',
        parent=expected_path_spec)

    base_path_specs = test_hasher.GetBasePathSpecs(path)
    self.assertEqual(base_path_specs, [expected_path_spec])


class OutputWriterTest(test_lib.BaseTestCase):
  """Tests for the output writer."""

  def testInitialize(self):
    """Tests the __init__ function."""
    output_writer = recursive_hasher.OutputWriter()
    self.assertIsNotNone(output_writer)

  # TODO: add tests for _EncodeString


class FileOutputWriterTest(test_lib.BaseTestCase):
  """Tests for the file output writer."""

  def testWriteFileHash(self):
    """Tests the WriteFileHash function."""
    with test_lib.TempDirectory() as temp_directory:
      path = os.path.join(temp_directory, 'hashes.txt')
      output_writer = recursive_hasher.FileOutputWriter(path)

      output_writer.Open()
      output_writer.WriteFileHash(
          '/password.txt',
          '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252')
      output_writer.Close()

      with io.open(path, mode='rb') as file_object:
        output = file_object.read()

    expected_output = (
        '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252'
        '\t/password.txt').encode('utf-8')
    self.assertEqual(output.rstrip(), expected_output)


class StdoutWriterTest(test_lib.BaseTestCase):
  """Tests for the stdout output writer."""

  def testWriteFileHash(self):
    """Tests the WriteFileHash function."""
    with test_lib.TempDirectory() as temp_directory:
      original_stdout = sys.stdout

      path = os.path.join(temp_directory, 'hashes.txt')

      with io.open(path, mode='wt', encoding='utf-8') as file_object:
        sys.stdout = file_object

        output_writer = recursive_hasher.StdoutWriter()

        output_writer.Open()
        output_writer.WriteFileHash(
            '/password.txt',
            '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252')
        output_writer.Close()

      sys.stdout = original_stdout

      with io.open(path, mode='rb') as file_object:
        output = file_object.read()

    expected_output = (
        '02a2a6af2f1ecf4720d7d49d640f0d0a269a7ec733e41973bdd34f09dad0e252'
        '\t/password.txt').encode('utf-8')
    self.assertEqual(output.rstrip(), expected_output)


# TODO: add tests for Main


if __name__ == '__main__':
  unittest.main()
