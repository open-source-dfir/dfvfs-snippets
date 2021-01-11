#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Script to recursively calculate a message digest hash for every file."""

# If you update this script make sure to update the corresponding wiki page
# as well: https://github.com/log2timeline/dfvfs/wiki/Development

import abc
import argparse
import hashlib
import logging
import sys

from dfvfs.analyzer import analyzer
from dfvfs.analyzer import fvde_analyzer_helper
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.lib import errors as dfvfs_errors
from dfvfs.helpers import command_line
from dfvfs.helpers import volume_scanner
from dfvfs.resolver import resolver


try:
  # Disable experimental FVDE support.
  analyzer.Analyzer.DeregisterHelper(fvde_analyzer_helper.FVDEAnalyzerHelper())
except KeyError:
  pass


class RecursiveHasher(volume_scanner.VolumeScanner):
  """Recursively calculates message digest hashes of data streams."""

  # Class constant that defines the default read buffer size.
  _READ_BUFFER_SIZE = 16 * 1024 * 1024

  # List of tuple that contain:
  #    tuple: full path represented as a tuple of path segments
  #    str: data stream name
  _PATHS_TO_IGNORE = frozenset([
      (('$BadClus', ), '$Bad')])

  _NON_PRINTABLE_CHARACTERS = list(range(0, 0x20)) + list(range(0x7f, 0xa0))
  _ESCAPE_CHARACTERS = str.maketrans({
      value: '\\x{0:02x}'.format(value)
      for value in _NON_PRINTABLE_CHARACTERS})

  def _CalculateHashDataStream(self, file_entry, data_stream_name):
    """Calculates a message digest hash of the data of the file entry.

    Args:
      file_entry (dfvfs.FileEntry): file entry.
      data_stream_name (str): name of the data stream.

    Returns:
      str: digest hash or None.
    """
    if file_entry.IsDevice() or file_entry.IsPipe() or file_entry.IsSocket():
      # Ignore devices, FIFOs/pipes and sockets.
      return None

    hash_context = hashlib.sha256()

    try:
      file_object = file_entry.GetFileObject(data_stream_name=data_stream_name)
    except IOError as exception:
      logging.warning((
          'Unable to open path specification:\n{0:s}'
          'with error: {1!s}').format(
              file_entry.path_spec.comparable, exception))
      return None

    if not file_object:
      return None

    try:
      data = file_object.read(self._READ_BUFFER_SIZE)
      while data:
        hash_context.update(data)
        data = file_object.read(self._READ_BUFFER_SIZE)
    except IOError as exception:
      logging.warning((
          'Unable to read from path specification:\n{0:s}'
          'with error: {1!s}').format(
              file_entry.path_spec.comparable, exception))
      return None

    finally:
      file_object.close()

    return hash_context.hexdigest()

  def _CalculateHashesFileEntry(
      self, file_system, file_entry, parent_path_segments, output_writer):
    """Recursive calculates hashes starting with the file entry.

    Args:
      file_system (dfvfs.FileSystem): file system.
      file_entry (dfvfs.FileEntry): file entry.
      parent_path_segments (str): path segments of the full path of the parent
          file entry.
      output_writer (StdoutWriter): output writer.
    """
    path_segments = parent_path_segments + [file_entry.name]
    lookup_path = tuple(path_segments[1:])

    for data_stream in file_entry.data_streams:
      hash_value = None
      if (lookup_path, data_stream.name) not in self._PATHS_TO_IGNORE:
        hash_value = self._CalculateHashDataStream(file_entry, data_stream.name)

      display_path = self._GetDisplayPath(
          file_entry.path_spec, path_segments, data_stream.name)
      output_writer.WriteFileHash(display_path, hash_value or 'N/A')

    try:
      for sub_file_entry in file_entry.sub_file_entries:
        self._CalculateHashesFileEntry(
            file_system, sub_file_entry, path_segments, output_writer)

    except (IOError, dfvfs_errors.AccessError,
            dfvfs_errors.BackEndError) as exception:
      logging.warning((
          'Unable to open path specification:\n{0:s}'
          'with error: {1!s}').format(
              file_entry.path_spec.comparable, exception))

  def _GetDisplayPath(self, path_spec, path_segments, data_stream_name):
    """Retrieves a path to display.

    Args:
      path_spec (dfvfs.PathSpec): path specification of the file entry.
      path_segments (list[str]): path segments of the full path of the file
          entry.
      data_stream_name (str): name of the data stream.

    Returns:
      str: path to display.
    """
    display_path = ''

    if path_spec.HasParent():
      parent_path_spec = path_spec.parent
      if parent_path_spec and parent_path_spec.type_indicator == (
          dfvfs_definitions.TYPE_INDICATOR_TSK_PARTITION):
        display_path = ''.join([display_path, parent_path_spec.location])

    path_segments = [
        segment.translate(self._ESCAPE_CHARACTERS) for segment in path_segments]
    display_path = ''.join([display_path, '/'.join(path_segments)])

    if data_stream_name:
      data_stream_name = data_stream_name.translate(self._ESCAPE_CHARACTERS)
      display_path = ':'.join([display_path, data_stream_name])

    return display_path or '/'

  def CalculateHashes(self, base_path_specs, output_writer):
    """Recursive calculates hashes starting with the base path specification.

    Args:
      base_path_specs (list[dfvfs.PathSpec]): source path specification.
      output_writer (StdoutWriter): output writer.
    """
    for base_path_spec in base_path_specs:
      file_system = resolver.Resolver.OpenFileSystem(base_path_spec)
      file_entry = resolver.Resolver.OpenFileEntry(base_path_spec)
      if file_entry is None:
        logging.warning('Unable to open base path specification:\n{0:s}'.format(
            base_path_spec.comparable))
        continue

      self._CalculateHashesFileEntry(file_system, file_entry, [], output_writer)


class OutputWriter(object):
  """Output writer interface."""

  def __init__(self, encoding='utf-8'):
    """Initializes an output writer.

    Args:
      encoding (Optional[str]): input encoding.
    """
    super(OutputWriter, self).__init__()
    self._encoding = encoding
    self._errors = 'strict'

  def _EncodeString(self, string):
    """Encodes the string.

    Args:
      string (str): string to encode.

    Returns:
      bytes: encoded string.
    """
    try:
      # Note that encode() will first convert string into a Unicode string
      # if necessary.
      encoded_string = string.encode(self._encoding, errors=self._errors)
    except UnicodeEncodeError:
      if self._errors == 'strict':
        logging.error(
            'Unable to properly write output due to encoding error. '
            'Switching to error tolerant encoding which can result in '
            'non Basic Latin (C0) characters to be replaced with "?" or '
            '"\\ufffd".')
        self._errors = 'replace'

      encoded_string = string.encode(self._encoding, errors=self._errors)

    return encoded_string

  @abc.abstractmethod
  def Close(self):
    """Closes the output writer object."""

  @abc.abstractmethod
  def Open(self):
    """Opens the output writer object."""

  @abc.abstractmethod
  def WriteFileHash(self, path, hash_value):
    """Writes the file path and hash.

    Args:
      path (str): path of the file.
      hash_value (str): message digest hash calculated over the file data.
    """


class FileOutputWriter(OutputWriter):
  """Output writer that writes to a file."""

  def __init__(self, path, encoding='utf-8'):
    """Initializes an output writer.

    Args:
      path (str): name of the path.
      encoding (Optional[str]): input encoding.
    """
    super(FileOutputWriter, self).__init__(encoding=encoding)
    self._file_object = None
    self._path = path

  def Close(self):
    """Closes the output writer object."""
    self._file_object.close()

  def Open(self):
    """Opens the output writer object."""
    # Using binary mode to make sure to write Unix end of lines, so we can
    # compare output files cross-platform.
    self._file_object = open(self._path, 'wb')

  def WriteFileHash(self, path, hash_value):
    """Writes the file path and hash to file.

    Args:
      path (str): path of the file.
      hash_value (str): message digest hash calculated over the file data.
    """
    string = '{0:s}\t{1:s}\n'.format(hash_value, path)

    encoded_string = self._EncodeString(string)
    self._file_object.write(encoded_string)


class StdoutWriter(OutputWriter):
  """Output writer that writes to stdout."""

  def Close(self):
    """Closes the output writer object."""

  def Open(self):
    """Opens the output writer object."""

  def WriteFileHash(self, path, hash_value):
    """Writes the file path and hash to stdout.

    Args:
      path (str): path of the file.
      hash_value (str): message digest hash calculated over the file data.
    """
    print('{0:s}\t{1:s}'.format(hash_value, path))


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      'Calculates a message digest hash for every file in a directory or '
      'storage media image.'))

  argument_parser.add_argument(
      '--back_end', '--back-end', dest='back_end', action='store',
      metavar='NTFS', default=None, help='preferred dfVFS back-end.')

  argument_parser.add_argument(
      '--output_file', '--output-file', dest='output_file', action='store',
      metavar='source.hashes', default=None, help=(
          'path of the output file, default is to output to stdout.'))

  argument_parser.add_argument(
      '--partitions', '--partition', dest='partitions', action='store',
      type=str, default=None, help=(
          'Define partitions to be processed. A range of '
          'partitions can be defined as: "3..5". Multiple partitions can '
          'be defined as: "1,3,5" (a list of comma separated values). '
          'Ranges and lists can also be combined as: "1,3..5". The first '
          'partition is 1. All partitions can be specified with: "all".'))

  argument_parser.add_argument(
      '--snapshots', '--snapshot', dest='snapshots', action='store', type=str,
      default=None, help=(
          'Define snapshots to be processed. A range of snapshots can be '
          'defined as: "3..5". Multiple snapshots can be defined as: "1,3,5" '
          '(a list of comma separated values). Ranges and lists can also be '
          'combined as: "1,3..5". The first snapshot is 1. All snapshots can '
          'be specified with: "all".'))

  argument_parser.add_argument(
      '--volumes', '--volume', dest='volumes', action='store', type=str,
      default=None, help=(
          'Define volumes to be processed. A range of volumes can be defined '
          'as: "3..5". Multiple volumes can be defined as: "1,3,5" (a list '
          'of comma separated values). Ranges and lists can also be combined '
          'as: "1,3..5". The first volume is 1. All volumes can be specified '
          'with: "all".'))

  argument_parser.add_argument(
      'source', nargs='?', action='store', metavar='image.raw',
      default=None, help='path of the directory or storage media image.')

  options = argument_parser.parse_args()

  if not options.source:
    print('Source value is missing.')
    print('')
    argument_parser.print_help()
    print('')
    return False

  logging.basicConfig(
      level=logging.INFO, format='[%(levelname)s] %(message)s')

  if options.output_file:
    output_writer = FileOutputWriter(options.output_file)
  else:
    output_writer = StdoutWriter()

  try:
    output_writer.Open()
  except IOError as exception:
    print('Unable to open output writer with error: {0!s}.'.format(
        exception))
    print('')
    return False

  if options.back_end == 'EXT':
    dfvfs_definitions.PREFERRED_EXT_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_EXT)

  elif options.back_end == 'HFS':
    dfvfs_definitions.PREFERRED_HFS_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_HFS)

  elif options.back_end == 'NTFS':
    dfvfs_definitions.PREFERRED_NTFS_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_NTFS)

  elif options.back_end == 'TSK':
    dfvfs_definitions.PREFERRED_EXT_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_TSK)
    dfvfs_definitions.PREFERRED_HFS_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_TSK)
    dfvfs_definitions.PREFERRED_NTFS_BACK_END = (
        dfvfs_definitions.TYPE_INDICATOR_TSK)

  mediator = command_line.CLIVolumeScannerMediator()
  recursive_hasher = RecursiveHasher(mediator=mediator)

  volume_scanner_options = volume_scanner.VolumeScannerOptions()
  volume_scanner_options.partitions = mediator.ParseVolumeIdentifiersString(
      options.partitions)

  if options.snapshots == 'none':
    volume_scanner_options.snapshots = ['none']
  else:
    volume_scanner_options.snapshots = mediator.ParseVolumeIdentifiersString(
        options.snapshots)

  volume_scanner_options.volumes = mediator.ParseVolumeIdentifiersString(
      options.volumes)

  return_value = True

  try:
    base_path_specs = recursive_hasher.GetBasePathSpecs(
        options.source, options=volume_scanner_options)
    if not base_path_specs:
      print('No supported file system found in source.')
      print('')
      return False

    recursive_hasher.CalculateHashes(base_path_specs, output_writer)

    print('')
    print('Completed.')

  except dfvfs_errors.ScannerError as exception:
    return_value = False

    print('')
    print('[ERROR] {0!s}'.format(exception))

  except dfvfs_errors.UserAbort as exception:
    return_value = False

    print('')
    print('Aborted.')

  output_writer.Close()

  return return_value


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
