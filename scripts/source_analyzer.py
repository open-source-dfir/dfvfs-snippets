#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Script to analyze a source device, file or directory."""

import argparse
import locale
import logging
import os
import sys

from dfvfs.credentials import manager as credentials_manager
from dfvfs.helpers import command_line
from dfvfs.helpers import source_scanner
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.resolver import resolver

from scripts import helpers


class SourceAnalyzer(object):
  """Analyzer to recursively check for volumes and file systems."""

  # Class constant that defines the default read buffer size.
  _READ_BUFFER_SIZE = 32768

  def __init__(self, auto_recurse=True, mediator=None):
    """Initializes a source analyzer.

    Args:
      auto_recurse (Optional[bool]): True if the scan should automatically
          recurse as far as possible.
      mediator (Optional[VolumeScannerMediator]): a volume scanner mediator.
    """
    super(SourceAnalyzer, self).__init__()
    self._auto_recurse = auto_recurse
    self._encode_errors = 'strict'
    self._mediator = mediator
    self._preferred_encoding = locale.getpreferredencoding()
    self._source_scanner = source_scanner.SourceScanner()

  def Analyze(self, source_path, output_writer):
    """Analyzes the source.

    Args:
      source_path (str): the source path.
      output_writer (StdoutWriter): the output writer.

    Raises:
      RuntimeError: if the source path does not exists, or if the source path
          is not a file or directory, or if the format of or within the source
          file is not supported.
    """
    if (not source_path.startswith('\\\\.\\') and
        not os.path.exists(source_path)):
      raise RuntimeError('No such source: {0:s}.'.format(source_path))

    scan_context = source_scanner.SourceScannerContext()
    scan_path_spec = None
    scan_step = 0

    scan_context.OpenSourcePath(source_path)

    while True:
      self._source_scanner.Scan(
          scan_context, auto_recurse=self._auto_recurse,
          scan_path_spec=scan_path_spec)

      if not scan_context.updated:
        break

      if not self._auto_recurse:
        output_writer.WriteScanContext(scan_context, scan_step=scan_step)
      scan_step += 1

      # The source is a directory or file.
      if scan_context.source_type in (
          dfvfs_definitions.SOURCE_TYPE_DIRECTORY,
          dfvfs_definitions.SOURCE_TYPE_FILE):
        break

      # The source scanner found a locked volume, e.g. an encrypted volume,
      # and we need a credential to unlock the volume.
      for locked_scan_node in scan_context.locked_scan_nodes:
        credentials = credentials_manager.CredentialsManager.GetCredentials(
            locked_scan_node.path_spec)

        self._mediator.UnlockEncryptedVolume(
            self._source_scanner, scan_context, locked_scan_node, credentials)

      if not self._auto_recurse:
        scan_node = scan_context.GetUnscannedScanNode()
        if not scan_node:
          return
        scan_path_spec = scan_node.path_spec

    if self._auto_recurse:
      output_writer.WriteScanContext(scan_context)


class StdoutWriter(command_line.StdoutOutputWriter):
  """Stdout output writer."""

  def WriteScanContext(self, scan_context, scan_step=None):
    """Writes the source scanner context to stdout.

    Args:
      scan_context (SourceScannerContext): the source scanner context.
      scan_step (Optional[int]): the scan step, where None represents no step.
    """
    if scan_step is not None:
      self.Write('Scan step: {0:d}\n'.format(scan_step))

    self.Write('Source type\t\t: {0:s}\n'.format(scan_context.source_type))
    self.Write('\n')

    scan_node = scan_context.GetRootScanNode()
    self.WriteScanNode(scan_context, scan_node)
    self.Write('\n')

  def WriteScanNode(self, scan_context, scan_node, indentation=''):
    """Writes the source scanner node to stdout.

    Args:
      scan_context (SourceScannerContext): the source scanner context.
      scan_node (SourceScanNode): the scan node.
      indentation (Optional[str]): indentation.
    """
    if not scan_node:
      return

    values = []

    part_index = getattr(scan_node.path_spec, 'part_index', None)
    if part_index is not None:
      values.append('{0:d}'.format(part_index))

    store_index = getattr(scan_node.path_spec, 'store_index', None)
    if store_index is not None:
      values.append('{0:d}'.format(store_index))

    start_offset = getattr(scan_node.path_spec, 'start_offset', None)
    if start_offset is not None:
      values.append('start offset: {0:d} (0x{0:08x})'.format(start_offset))

    location = getattr(scan_node.path_spec, 'location', None)
    if location is not None:
      values.append('location: {0:s}'.format(location))

    values = ', '.join(values)

    flags = []
    if scan_node in scan_context.locked_scan_nodes:
      flags.append('[LOCKED]')

    type_indicator = scan_node.path_spec.type_indicator
    if type_indicator == dfvfs_definitions.TYPE_INDICATOR_TSK:
      file_system = resolver.Resolver.OpenFileSystem(scan_node.path_spec)
      if file_system.IsHFS():
        flags.append('[HFS/HFS+/HFSX]')
      elif file_system.IsNTFS():
        flags.append('[NTFS]')

    flags = ' '.join(flags)
    self.Write('{0:s}{1:s}: {2:s}{3:s}\n'.format(
        indentation, type_indicator, values, flags))

    indentation = '  {0:s}'.format(indentation)
    for sub_scan_node in scan_node.sub_nodes:
      self.WriteScanNode(scan_context, sub_scan_node, indentation=indentation)


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  argument_parser = argparse.ArgumentParser(description=(
      'Calculates a message digest hash for every file in a directory or '
      'storage media image.'))

  argument_parser.add_argument(
      'source', nargs='?', action='store', metavar='image.raw', default=None,
      help=('path of the directory or filename of a storage media image '
            'containing the file.'))

  argument_parser.add_argument(
      '--back_end', '--back-end', dest='back_end', action='store',
      metavar='NTFS', default=None, help='preferred dfVFS back-end.')

  argument_parser.add_argument(
      '--no-auto-recurse', '--no_auto_recurse', dest='no_auto_recurse',
      action='store_true', default=False, help=(
          'Indicate that the source scanner should not auto-recurse.'))

  options = argument_parser.parse_args()

  if not options.source:
    print('Source value is missing.')
    print('')
    argument_parser.print_help()
    print('')
    return False

  helpers.SetDFVFSBackEnd(options.back_end)

  logging.basicConfig(
      level=logging.INFO, format='[%(levelname)s] %(message)s')

  output_writer = StdoutWriter()

  mediator = command_line.CLIVolumeScannerMediator(
      output_writer=output_writer)

  source_analyzer = SourceAnalyzer(
      auto_recurse=not options.no_auto_recurse, mediator=mediator)

  return_value = True

  try:
    source_analyzer.Analyze(options.source, output_writer)

    print('Completed.')

  except KeyboardInterrupt:
    return_value = False

    print('Aborted by user.')

  return return_value


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
