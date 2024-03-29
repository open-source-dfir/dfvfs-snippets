#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the file entry lister script."""

import io
import os
import sys
import unittest

from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.resolver import resolver
from dfvfs.path import factory as path_spec_factory

from scripts import list_file_entries

from tests import test_lib


class TestOutputWriter(list_file_entries.OutputWriter):
  """Output writer for testing the file entry lister script.

  Attributes:
    paths (list[str]): paths of the file entries.
  """

  def __init__(self, encoding='utf-8'):
    """Initializes an output writer.

    Args:
      encoding (Optional[str]): input encoding.
    """
    super(TestOutputWriter, self).__init__(encoding=encoding)
    self.paths = []

  def Close(self):
    """Closes the output writer object."""
    return

  def Open(self):
    """Opens the output writer object."""
    return

  def WriteFileEntry(self, path):
    """Writes the file path.

    Args:
      path (str): path of the file.
    """
    self.paths.append(path)


class FileEntryListerTest(test_lib.BaseTestCase):
  """Tests for the file entry lister."""

  # pylint: disable=protected-access

  def testListFileEntry(self):
    """Tests the _ListFileEntry function."""
    path = self._GetTestFilePath(['image.qcow2'])
    self._SkipIfPathNotExists(path)

    test_lister = list_file_entries.FileEntryLister()

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
    test_lister._ListFileEntry(file_system, file_entry, [''], output_writer)

    self.assertEqual(len(output_writer.paths), 1)

    expected_paths = ['/passwords.txt']
    self.assertEqual(output_writer.paths, expected_paths)

  def testListFileEntries(self):
    """Tests the ListFileEntries function."""
    path = self._GetTestFilePath(['image.qcow2'])
    self._SkipIfPathNotExists(path)

    test_lister = list_file_entries.FileEntryLister()

    base_path_specs = test_lister.GetBasePathSpecs(path)
    output_writer = TestOutputWriter()
    test_lister.ListFileEntries(base_path_specs, output_writer)

    expected_paths = [
        '/',
        '/lost+found',
        '/a_directory',
        '/a_directory/another_file',
        '/a_directory/a_file',
        '/passwords.txt']

    if dfvfs_definitions.PREFERRED_EXT_BACK_END == (
        dfvfs_definitions.TYPE_INDICATOR_TSK):
      expected_paths.append('/$OrphanFiles')

    self.assertEqual(len(output_writer.paths), len(expected_paths))
    self.assertEqual(output_writer.paths, expected_paths)

  def testGetBasePathSpecs(self):
    """Tests the GetBasePathSpecs function."""
    path = self._GetTestFilePath(['image.qcow2'])
    self._SkipIfPathNotExists(path)

    test_lister = list_file_entries.FileEntryLister()

    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location=path)
    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_QCOW, parent=expected_path_spec)
    expected_path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.PREFERRED_EXT_BACK_END, location='/',
        parent=expected_path_spec)

    base_path_specs = test_lister.GetBasePathSpecs(path)
    self.assertEqual(base_path_specs, [expected_path_spec])


class OutputWriterTest(test_lib.BaseTestCase):
  """Tests for the output writer."""

  def testInitialize(self):
    """Tests the __init__ function."""
    output_writer = list_file_entries.OutputWriter()
    self.assertIsNotNone(output_writer)

  # TODO: add tests for _EncodeString


class FileOutputWriterTest(test_lib.BaseTestCase):
  """Tests for the file output writer."""

  def testWriteFileEntry(self):
    """Tests the WriteFileEntry function."""
    with test_lib.TempDirectory() as temp_directory:
      path = os.path.join(temp_directory, 'paths.txt')
      output_writer = list_file_entries.FileOutputWriter(path)

      output_writer.Open()
      output_writer.WriteFileEntry('/password.txt')
      output_writer.Close()

      with io.open(path, mode='rb') as file_object:
        output = file_object.read()

    expected_output = '/password.txt'.encode('utf-8')
    self.assertEqual(output.rstrip(), expected_output)


class StdoutWriterTest(test_lib.BaseTestCase):
  """Tests for the stdout output writer."""

  def testWriteFileEntry(self):
    """Tests the WriteFileEntry function."""
    with test_lib.TempDirectory() as temp_directory:
      original_stdout = sys.stdout

      path = os.path.join(temp_directory, 'hashes.txt')

      with io.open(path, mode='wt', encoding='utf-8') as file_object:
        sys.stdout = file_object

        output_writer = list_file_entries.StdoutWriter()

        output_writer.Open()
        output_writer.WriteFileEntry('/password.txt')
        output_writer.Close()

      sys.stdout = original_stdout

      with io.open(path, mode='rb') as file_object:
        output = file_object.read()

    expected_output = '/password.txt'.encode('utf-8')
    self.assertEqual(output.rstrip(), expected_output)


# TODO: add tests for Main


if __name__ == '__main__':
  unittest.main()
