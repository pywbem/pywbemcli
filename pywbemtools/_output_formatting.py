# (C) Copyright 2017 IBM Corp.
# (C) Copyright 2017-2021 Inova Development Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Functions that help defining or validating output formats, and that perform
output formatting.
"""

from __future__ import absolute_import, print_function, unicode_literals

from textwrap import fill
from operator import itemgetter
from collections import namedtuple
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict  # pylint: disable=import-error

import six
import click
import tabulate

from pywbem import CIMInstanceName


DEFAULT_MAX_CELL_WIDTH = 100


##############################################################
#
#     General option output format definitions and support for
#     validating output formats
#
##############################################################

# Definition of the format keywords within each format group
TABLE_FORMATS = ('table', 'plain', 'simple', 'grid', 'psql', 'rst', 'html')
CIM_OBJECT_FORMATS = ('mof', 'xml', 'repr', 'txt')
TEXT_FORMATS = ('text',)

# Definition of the default format for each format group
DEFAULT_CIM_FORMAT = 'mof'
DEFAULT_TABLE_FORMAT = 'simple'
DEFAULT_TEXT_FORMAT = 'text'

# Definition of the format groups.
# The order of the dictionary items determines the priority when automatically
# selecting a matching format group.
GROUPVALUES = namedtuple('GROUPVALUES', 'keywords default')
OUTPUT_FORMAT_GROUPS = OrderedDict(
    [('CIM', GROUPVALUES(CIM_OBJECT_FORMATS, DEFAULT_CIM_FORMAT)),
     ('TABLE', GROUPVALUES(TABLE_FORMATS, DEFAULT_TABLE_FORMAT)),
     ('TEXT', GROUPVALUES(TEXT_FORMATS, DEFAULT_TEXT_FORMAT))])

# All of the format keywords
OUTPUT_FORMATS = tuple(item for fmts in OUTPUT_FORMAT_GROUPS.values()
                       for item in fmts.keywords)


def output_format_is_table(output_format):
    """
    Return boolean indicating whether an output format is a table format.

    Parameters:

      output_format (:term:`string`):
         The output format keyword (e.g. 'mof') to be checked.

    Returns:
      bool: Boolean indicating whether the output format is a table format.
    """
    return output_format in TABLE_FORMATS


def output_format_is_cimobject(output_format):
    """
    Return boolean indicating whether an output format is a table format.

    Parameters:

      output_format (:term:`string`):
         The output format keyword (e.g. 'mof') to be checked.

    Returns:
      bool: Boolean indicating whether the output format is a table format.
    """
    return output_format in CIM_OBJECT_FORMATS


def output_format_in_groups(output_format, format_groups):
    """
    Return boolean indicating whether an output format is in a given format
    group or list thereof.

    Parameters:

      output_format (:term:`string`):
         The output format keyword (e.g. 'mof') to be checked.

      format_groups (:term:`string` or list of :term:`string`):
         The name of the format group (or list thereof) to check against.

    Returns:
      bool: Boolean indicating whether the output format is in the format
      group or list thereof.

    Raises:
      KeyError: format_groups parameter is not a valid format group name.
    """
    if isinstance(format_groups, (list, tuple)):
        for group in format_groups:
            if output_format_in_groups(output_format, group):
                return True
        return False
    return output_format in OUTPUT_FORMAT_GROUPS[format_groups]


def validate_output_format(output_format, valid_format_groups,
                           default_format=None):
    """
    Validate an output format against a list of valid format groups, or select
    a default output format if no output format is specified.

    The returned output format will be the specified output format, or a default
    if no output format is specified. The default will be:
    - the default output format keyword (default_format parameter), if specified
    - the default format of the first valid format group (valid_format_groups
      parameter), if specified
    - the default format of the 'CIM' format group

    An exception is raised when the specified output format is not in the
    specified valid format groups.

    Parameters:

      output_format (:term:`string` or `None`):
        The output format keyword (e.g. 'mof') to be validated, or `None` if
        no output format is specified and a default should be selected.

      valid_format_groups (list of :term:`string` or :term:`string` or `None`):
        The names of the valid format groups, or `None` indicating that any
        format group is valid.

      default_format (:term:`string` or `None`):
        Default output format keyword, or `None`if no default is specified.

    Returns:
       :term:`string`: The keyword for the output format to be used.

    Raises:
        click.ClickException: The specified output format is not in a specified
          format group.
    """

    if isinstance(valid_format_groups, six.string_types):
        valid_format_groups = [valid_format_groups]

    if valid_format_groups:
        assert all(element in OUTPUT_FORMAT_GROUPS for element in
                   valid_format_groups)
    if default_format:
        assert default_format in OUTPUT_FORMATS

    if output_format:

        if valid_format_groups is None:
            return output_format

        for group, value in OUTPUT_FORMAT_GROUPS.items():
            if group in valid_format_groups:
                if output_format in value.keywords:
                    return output_format

        # Invalid output format, raise exception
        valid_formats = ""
        for name, value in OUTPUT_FORMAT_GROUPS.items():
            fmt_list = value.keywords
            if name in valid_format_groups:
                if valid_formats:
                    valid_formats += "; "
                valid_formats += '{0} formats: "({1})"'.format(
                    name, '", "'.join(fmt_list))
        raise click.ClickException('Output format "{}" not allowed for this '
                                   'command. Only {} allowed.'.
                                   format(output_format, valid_formats))

    assert output_format is None

    if default_format:
        return default_format

    if valid_format_groups is None:
        return OUTPUT_FORMAT_GROUPS['CIM'].default

    for group, value in OUTPUT_FORMAT_GROUPS.items():
        if valid_format_groups[0] == group:
            return value.default

    return OUTPUT_FORMAT_GROUPS['CIM'].default


######################################################################
#
#  General common functions
#
######################################################################


def warning_msg(msg):
    """Issue the msg param as warning prefixed by WARNING: to stderr"""
    click.echo('WARNING: {}'.format(msg), err=True)


def display_text(text, output_format=None):  # pylint: disable=unused-argument
    """
    Display the text output format. Currently this simply outputs to
    click.echo
    """
    click.echo(text)


def format_keys(obj, max_width):
    """
    Format the keys of a dictionary of keybindings as text for display. Formats
    multiple keybindings on each line within the max_width

    Parameters:

      obj (:class:`pwbem.CIMInstanceName`):
        Instance name from which keybindings are to be extracted for
        formatting.

    Returns:
        :term:`string` containing the keys from the input obj formatted for
        display at within the defined width.
    """
    def get_wbemurikeys(obj):
        """
        Create wbem_uri from CIMInstanceName and separate out key component
        for return.
        """
        wbem_uri = obj.to_wbem_uri()
        wbem_uri_keys = wbem_uri[wbem_uri.find('.'):]
        wbem_uri_keys = wbem_uri_keys[1:]
        return wbem_uri_keys

    assert isinstance(obj, CIMInstanceName)
    # clear the host and namespace
    myobj = obj.copy()
    myobj.host = None
    myobj.namespace = None
    wbem_uri_keys = get_wbemurikeys(myobj)

    # Too long for width. Fold the keys on multiple lines
    if len(wbem_uri_keys) > max_width:
        wbem_uri_keys = ''
        line_len = 0
        for key, value in myobj.keybindings.items():
            one_key_obj = get_wbemurikeys((CIMInstanceName('x', {key: value})))
            if wbem_uri_keys:
                if line_len + len(one_key_obj) > max_width:
                    wbem_uri_keys += '\n{}'.format(one_key_obj)
                    line_len = 0
                else:
                    wbem_uri_keys += ',{}'.format(one_key_obj)
                    line_len += len(one_key_obj) + 1

            else:  # must put on first line even if too long
                wbem_uri_keys += one_key_obj
                line_len = len(one_key_obj) + 1

    return wbem_uri_keys


def hide_empty_columns(headers, rows):
    """
    Removes columns from rows if the colmuns are considered empty.
    The definiton of an empty row is:
    1. All entries for the column in all rows are None or "" if type string.
    2. All entries for the column in all rows are None if number.

    Parameters:
      headers (list of :term:`string`)
        The strings that represent the column titles of an array of rows.

      rows (list of list of TBD):
        The rows of a table where each row is a list of the items that
        represent the columns of the row.

    Returns new rows and headers
    """
    def column_is_empty(rows, column):
        """
        Determine if entries for defined column in all rows are considered
        empty.
        Returns True if all are empty. Otherwise returns False
        """
        for row in rows:
            if isinstance(row[column], six.integer_types) and \
                    row[column] is not None:
                return False
            if row[column]:
                return False
        return True

    # Remove empty rows
    len_hdr = len(headers)
    for row in rows:
        assert len(row) == len_hdr, "row: {}\nhdrs: {}". \
            format(row, headers)
    for column in range(len(headers) - 1, -1, -1):
        if column_is_empty(rows, column):
            if isinstance(headers, tuple):
                headersl = list(headers)
                del headersl[column]
                headers = tuple(headersl)
            else:
                del headers[column]
            for row in rows:
                del row[column]

    return headers, rows


def format_table(rows, headers, title=None, table_format='simple',
                 sort_columns=None, hide_empty_cols=None, float_fmt=None):
    """
    General print table function.  Prints a list of lists in a
    table format where each inner list is a row.
    This code is temporary while the tabulate package is updated

    Parameters:

      headers (list strings):
        where each string is a table column name or None if no header is to be
        attached

      table_data (list of lists):
        where each the top level iterables represents the list of rows
        and each row is an iterable of strings for the data in that row.

      title (:term:`string`):
         Optional title to be places io the output above the table.
         No title is output if this parameter is None

      table_format (:term:`string`):
        Output format defined by the string and limited to one of the
        choice of table formats defined in TABLE_FORMATS list

      output_file (:term:`string`):
        If not None, a file name to which the output formatted data is sent.

      sort_columns (int or list of int that defines sort):
        Defines the cols that will be sorted. If int, it defines the column
        that will be sorted. If list of int, the sort is in sort order of
        cols in the list (i.e. minor sorts to the left, major sorts to the
        right). Note that entries in each row of the columns to be sorted
        must be of the same type (int, str, etc.) to be sortable.

    hide_empty_cols (:class:`py:bool`):
        If this flag is True any columns that are completely blank are
        hiddend and the column header is removed from the headers.
        Uses the function hide_empty_columns

    float_fmt (:term:`string` or list of :term:`string`):
        String defining the formating of floating point format, either
        universal for all floating point if a single string or for selected
        columns if a list is provided.
        The string defines the number of decimals after the decimal point as
        ".<number>f". Thus ".4f" tells the formatter to use 4 digits after the
        decimal point

    Returns:
        :term:`string`: Returns the formatted table as a string

    Raises:
        click.ClickException if invalid table format string
    """
    if hide_empty_cols:
        headers, rows = hide_empty_columns(headers, rows)
    if sort_columns is not None:
        if isinstance(sort_columns, int):
            rows = sorted(rows, key=itemgetter(sort_columns))
        elif isinstance(sort_columns, (list, tuple)):
            rows = sorted(rows, key=itemgetter(*sort_columns))
        else:
            assert False, "Sort_columns must be int or list/tuple of int"

    if table_format is None:
        table_format = 'table'
    if table_format == 'table':
        table_format = 'psql'
    if not output_format_is_table(table_format):
        raise click.ClickException('Invalid table format {}.'
                                   .format(table_format))

    # Required because tabulate applies an internally defined format
    # when floatfmt not defined.
    if float_fmt:
        result = tabulate.tabulate(rows, headers, tablefmt=table_format,
                                   floatfmt=float_fmt)
    else:
        result = tabulate.tabulate(rows, headers, tablefmt=table_format)

    if title:
        if table_format == 'html':
            # Insert caption element immediatly after table
            assert result.startswith("<table>")
            replacement = "<table>\n<caption>{0}</caption>".format(title)
            result = result.replace("<table>", replacement, 1)
        else:
            result = '{0}\n{1}'.format(title, result)
    return result


def fold_strings(input_strings, max_width, break_long_words=False,
                 break_on_hyphens=False, fold_list_items=False, separator=', ',
                 initial_indent='', subsequent_indent=''):
    """
    Fold a string or a list/tuple of strings within a maximum width and return
    a folded string that fits within the width defined by max_width. If input
    is a list of strings, the fold_list_itmes defines whether they create
    separate lines in the output or are concatenated into a single string
    before folding the string. This implementation refolds strings that already
    contain EOL characters and removes any existing folds that do not match the
    max_width criteria.  Lists of strings may be folded with one string per
    line or concatenated and then folded.

    Parameters:

      input_strings (:term:`string` or list of :term:`string`):
        The string that will be contents of into the cell. This string may
        already include multiple lines.

      max_width (:term:`integer`):
        Maximum width of cell containing the resulting string.  Data is
        folded into multiple lines to fit into this width.

      break_long_words (:class:`py:bool`):
        Boolean that forces long words to be broken if True
        If False, long words will not break at the max width

      break_on_hyphens (:class:`py:bool`):
        If True use hypens as word separator.

      fold_list_items (:class:`py:bool`):
        If True, force fold for each item in list/tupe of input strings if
        single line concatenation is longer than max_width. Otherwise list is
        contatenated and the result folded.

      separator (:term:`string`):
        String that is separator between list items when folded into
        string.

      initial_indent (:term:`integer` or :term:`string`):
        Integer  or string defining the number of characters of indent for
        the first line if single string or the first line of each string in
        the list if input_strings is a list and fold_list_items is True.

      subsequent_indent (:term:`integer`):
        Integer or string, defining the number of characters of indent for
        the all but the first lineif single string or the first line of
        each string in the list if input_strings is a list and
        fold_list_items is True.

    Returns:
        String representing the folded input_strings
    """
    def indent_str(indent):
        """
        Maps indent to string of indent characters if necessary.
        If None, return None
        If integer, map to indent characters
        """
        if indent is None:
            return ""
        if isinstance(indent, six.string_types):
            return indent
        return ' ' * indent

    initial_indent = indent_str(initial_indent)
    subsequent_indent = indent_str(subsequent_indent)

    if isinstance(input_strings, (list, tuple)):
        if separator is None:
            separator = ', '
        build_str = separator.join(input_strings)
        # Return contatentated list if within cell width
        if len(build_str) <= max_width:
            return build_str

        if fold_list_items:
            folded_strings = []
            for str_item in input_strings:
                folded_strings.append(
                    fold_strings(str_item, max_width,
                                 break_long_words=break_long_words,
                                 break_on_hyphens=break_on_hyphens,
                                 initial_indent=initial_indent,
                                 subsequent_indent=subsequent_indent))
            return "\n".join(folded_strings)
        input_strings = build_str

    # process single string
    input_string = input_strings
    assert isinstance(input_string, six.string_types)

    if len(input_string) <= max_width:
        return input_string

    # use textwrap fill to fold the string
    folded_string = fill(input_string, max_width,
                         break_long_words=break_long_words,
                         break_on_hyphens=break_on_hyphens,
                         initial_indent=initial_indent,
                         subsequent_indent=subsequent_indent)

    return folded_string
