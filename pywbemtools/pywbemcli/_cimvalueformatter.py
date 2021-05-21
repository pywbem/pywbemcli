# (C) Copyright 2017 IBM Corp.
# (C) Copyright 2017 Inova Development Inc.
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
Pywbemcli function to format CIM values from properties and parameters into
strings that have defined folding rules and can fit into specific spaces like
table cells
"""

from __future__ import absolute_import, print_function, unicode_literals

import six

from pywbem import CIMInstance, CIMClass, CIMFloat, CIMInt

# Same as in pywbem.cimobj.py
try:
    from builtins import type as builtin_type
except ImportError:  # py2
    from __builtin__ import type as builtin_type


DEFAULT_MAX_CELL_WIDTH = 100

# Same as in pwbem.cimtypes.py
if six.PY2:
    # pylint: disable=invalid-name,undefined-variable
    _Longint = long  # noqa: F821
else:
    # pylint: disable=invalid-name
    _Longint = int


# Constants for string formatting
DEFAULT_INDENT = 3

#
#  NOTE: The following code was taken largely from pywbem methods that
#  prepare strings for MOF output. We kept the same basic formatting but
#  simplified slightly.
#  The goal is to create strings for property or parameter values that can be
#  placed in rows of a table and that follow the detailed formatting of MOF
#
#  The names were changed in some cases and all of the functions except
#  the function cimvalue_to_fmtd_string(...) are marked internal.
#
#
#  We have left most of the options in that are in pywbem because we are
#  unsure how this will be used and that can affect formatting in the future.
#


def _indent_str(indent):
    """
    Return a MOF indent pad unicode string from the indent integer variable
    that defines number of spaces to indent. Used to format MOF output.
    """
    return u''.ljust(indent, u' ')


def _mofval(value, indent, maxline, line_pos=0, end_space=0):
    """
    Low level function that returns the MOF representation of a non-string
    value (i.e. a value that cannot not be split into multiple parts, for
    example a numeric or boolean value).

    If the MOF representation of the value does not fit into the remaining
    space of the current line, it is put into a new line, considering the
    specified indentation.

    NOTE: This method is derived from pywbem mofval but differs in that we
    want to output even if we violate the maxline limit on the new line. This
    method favors outputting data over exceptions.

    Parameters:

      value (:term:`unicode string`): The non-string value. Must not be `None`.

      indent (:term:`integer`): Number of spaces to indent any new lines that
        are generated.

      maxline (:term:`integer`): Maximum line length for the generated MOF.

      line_pos (:term:`integer`): Length of content already on the current
        line.

      end_space (:term:`integer`): Length of space to be left free on the last
        line.

    Returns:

      tuple of
        * :term:`unicode string`: MOF string.
        * new line_pos
    """

    assert isinstance(value, six.text_type)

    # Check for output on current line
    # if fits or this is first entry on the line
    avl_len = maxline - line_pos - end_space
    if len(value) <= avl_len or line_pos == 0:
        line_pos += len(value)
        return value, line_pos

    mof_str = u'\n' + _indent_str(indent) + value
    line_pos = indent + len(value)
    return mof_str, line_pos


def _scalar_value_tomof(value, type, indent, maxline, line_pos=0, end_space=0,
                        avoid_splits=False, quote_strings=True):
    # pylint: disable=line-too-long,redefined-builtin
    """
    Return a MOF string representing a scalar CIM-typed value.

    `None` is returned as 'NULL'.

    NOTE: This code taken from pywbem 0.14.0

    Parameters:

      value (:term:`CIM data type`, :term:`number`, :class:`~pywbem.CIMInstance`, :class:`~pywbem.CIMClass`):
        The scalar CIM-typed value. May be `None`.

        Must not be an array/list/tuple. Must not be a :ref:`CIM object` other
        than those listed.

      type (string): CIM data type name.

      indent (:term:`integer`): Number of spaces to indent any new lines that
        are generated.

      maxline (:term:`integer`): Maximum line length for the generated MOF.

      line_pos (:term:`integer`): Length of content already on the current
        line.

      end_space (:term:`integer`): Length of space to be left free on the last
        line.

      avoid_splits (bool): Avoid splits at the price of starting a new line
        instead of using the current line.

      quote_strings (bool): If True, (the default) quote strings. If False
      prepare strings without the quote characters pre and post pending the
      strings and folded string parts.

    Returns:

      tuple of
        * :term:`unicode string`: MOF string.
        * new line_pos
    """  # noqa: E501

    if type == 'string':  # pylint: disable=no-else-raise
        if isinstance(value, six.string_types):
            return _mofstr(value, indent, maxline, line_pos, end_space,
                           avoid_splits, quote_char=None)

        if isinstance(value, (CIMInstance, CIMClass)):
            # embedded instance or class
            return _mofstr(value.tomof(), indent, maxline, line_pos, end_space,
                           avoid_splits)
        raise TypeError("Scalar value of CIM type {0} has invalid Python type "
                        "type {1} for conversion to a MOF string".format
                        (type, builtin_type(value)))

    elif type == 'char16':
        return _mofstr(value, indent, maxline, line_pos, end_space,
                       avoid_splits, quote_char=u"'")
    elif type == 'boolean':
        val = u'true' if value else u'false'
        return _mofval(val, indent, maxline, line_pos, end_space)
    elif type == 'datetime':
        val = six.text_type(value)
        return _mofstr(val, indent, maxline, line_pos, end_space, avoid_splits)
    elif type == 'reference':
        val = value.to_wbem_uri(format='standard')
        return _mofstr(val, indent, maxline, line_pos, end_space, avoid_splits)
    elif isinstance(value, (CIMFloat, CIMInt, int, _Longint)):
        val = six.text_type(value)
        return _mofval(val, indent, maxline, line_pos, end_space)
    else:
        assert isinstance(value, float), \
            "Scalar value of CIM type {0} has invalid Python type {1} " \
            "for conversion to a MOF string".format(type, builtin_type(value))
        val = repr(value)
        return _mofval(val, indent, maxline, line_pos, end_space)


def mof_escaped(strvalue):
    # Note: This is a raw docstring because it shows many backslashes, and
    # that avoids having to double them.
    r"""
    Return a MOF-escaped string from the input string.

    Parameters:

      strvalue (:term:`unicode string`): The string value. Must not be `None`.
        Special characters must not be backslash-escaped.

    Details on backslash-escaping:

    `DSP0004` defines that the character repertoire for MOF string constants
    is the entire repertoire for the CIM string datatype. That is, the entire
    Unicode character repertoire except for U+0000.

    The only character for which `DSP0004` requires the use of a MOF escape
    sequence in a MOF string constant, is the double quote (because a MOF
    string constant is enclosed in double quotes).

    `DSP0004` defines MOF escape sequences for several more characters, but it
    does not require their use in MOF. For example, it is valid for a MOF
    string constant to contain the (unescaped) characters U+000D (newline) or
    U+0009 (horizontal tab), and others.

    Processing the MOF escape sequences as unescaped characters may not be
    supported by MOF-related tools, and therefore this function plays it safe
    and uses the MOF escape sequences defined in `DSP0004` as much as possible.
    The following table shows the MOF escape sequences defined in `DSP0004`
    and whether they are used (i.e. generated) by this function:

    ========== ==== ===========================================================
    MOF escape Used Character
    sequence
    ========== ==== ===========================================================
    \b         yes  U+0008: Backspace
    \t         yes  U+0009: Horizontal tab
    \n         yes  U+000A: Line feed
    \f         yes  U+000C: Form feed
    \r         yes  U+000D: Carriage return
    \"         yes  U+0022: Double quote (") (required to be used)
    \'         yes  U+0027: Single quote (')
    \\         yes  U+005C: Backslash (\)
    \x<hex>    (1)  U+<hex>: Any UCS-2 character, where <hex> is one to four
                      hex digits, representing its UCS code position (this form
                      is limited to the UCS-2 character repertoire)
    \X<hex>    no   U+<hex>: Any UCS-2 character, where <hex> is one to four
                      hex digits, representing its UCS code position (this form
                      is limited to the UCS-2 character repertoire)
    ========== ==== ===========================================================

    (1) Yes, for all other characters in the so called "control range"
        U+0001..U+001F.
    """

    escaped_str = strvalue

    # Escape backslash (\)
    escaped_str = escaped_str.replace('\\', '\\\\')

    # Escape \b, \t, \n, \f, \r
    # Note, the Python escape sequences happen to be the same as in MOF
    escaped_str = escaped_str.\
        replace('\b', '\\b').\
        replace('\t', '\\t').\
        replace('\n', '\\n').\
        replace('\f', '\\f').\
        replace('\r', '\\r')

    # Escape remaining control characters (U+0001...U+001F), skipping
    # U+0008, U+0009, U+000A, U+000C, U+000D that are already handled.
    # We hard code it to be faster, plus we can easily skip already handled
    # chars.
    # The generic code would be (not skipping already handled chars):
    #     for cp in range(1, 32):
    #         c = six.unichr(cp)
    #         esc = '\\x{0:04X}'.format(cp)
    #         escaped_str = escaped_str.replace(c, esc)
    escaped_str = escaped_str.\
        replace(u'\u0001', '\\x0001').\
        replace(u'\u0002', '\\x0002').\
        replace(u'\u0003', '\\x0003').\
        replace(u'\u0004', '\\x0004').\
        replace(u'\u0005', '\\x0005').\
        replace(u'\u0006', '\\x0006').\
        replace(u'\u0007', '\\x0007').\
        replace(u'\u000B', '\\x000B').\
        replace(u'\u000E', '\\x000E').\
        replace(u'\u000F', '\\x000F').\
        replace(u'\u0010', '\\x0010').\
        replace(u'\u0011', '\\x0011').\
        replace(u'\u0012', '\\x0012').\
        replace(u'\u0013', '\\x0013').\
        replace(u'\u0014', '\\x0014').\
        replace(u'\u0015', '\\x0015').\
        replace(u'\u0016', '\\x0016').\
        replace(u'\u0017', '\\x0017').\
        replace(u'\u0018', '\\x0018').\
        replace(u'\u0019', '\\x0019').\
        replace(u'\u001A', '\\x001A').\
        replace(u'\u001B', '\\x001B').\
        replace(u'\u001C', '\\x001C').\
        replace(u'\u001D', '\\x001D').\
        replace(u'\u001E', '\\x001E').\
        replace(u'\u001F', '\\x001F')

    # Escape single and double quote
    escaped_str = escaped_str.replace('"', '\\"')
    escaped_str = escaped_str.replace("'", "\\'")

    return escaped_str


def _mofstr(value, indent, maxline, line_pos, end_space, avoid_splits=False,
            quote_char=u'"'):
    """
    Low level function that returns the MOF representation of a string value
    (i.e. a value that can be split into multiple parts, for example a string,
    reference or datetime typed value).

    The function performs the backslash-escaping of characters in the string
    (for details, see function mof_escaped()), handles the splitting into
    multiple string parts if the current line does not have sufficient space
    left, and surrounds the string parts (or the entire string, if it ends up
    having only one part) with the specified quote characters.

    The strategy for starting new lines and for splitting the string into parts
    is:

    * If the string fits into the current line, it is output.
    * If the 'avoid_splits' flag is set, a new line is generating. If the
      string fits onto the new line, it is output. Otherwise, the string is
      split into parts and these are output starting with the new line,
      generating additional new lines as needed.
    * If the 'avoid_splits' flag is not set, the string is split into parts and
      these are output starting with the current line, generating new lines as
      needed.
    * Strings are first tried to split after the rightmost space character that
      would still make it fit onto the line, and only if there is no space
      character in that range, the string is split at a non-space position.

    Parameters:

      value (:term:`unicode string`): The string value. Must not be `None`.
        Special characters must not be backslash-escaped.

      indent (:term:`integer`): Number of spaces to indent any new lines that
        are generated.

      maxline (:term:`integer`): Maximum line length for the generated string.

      line_pos (:term:`integer`): Length of content already on the current
        line.

      end_space (:term:`integer`): Length of space to be left free on the last
        line.

      avoid_splits (bool): Avoid splits at the price of starting a new line
        instead of using the current line.

      quote_char (:term:`unicode string` or None): Character to be used for
        surrounding the string parts with. For CIM string typed values, this
        must be a double quote (the default), and for CIM char16 typed values,
        this must be a single quote. The value of this may be None, in which
        case, no character will be used to surround the string parts.  The
        value None makes it possible to display cim values as strings in tables
        without the quote characters taking up space in the table.

    Returns:

      tuple of
        * :term:`unicode string`: MOF string.
        * new line_pos
    """

    assert isinstance(value, six.text_type)

    value = mof_escaped(value)

    quote_len = 2  # length of the quotes surrounding a string part
    new_line = u'\n' + _indent_str(indent)

    mof = []

    while True:

        # Prepare safety check for endless loops
        saved_value = value

        avl_len = maxline - line_pos - quote_len

        # Decide whether to start a new line
        if len(value) > avl_len - end_space:
            if avoid_splits or avl_len < 0:
                # Start a new line
                mof.append(new_line)
                line_pos = indent
                avl_len = maxline - indent - quote_len
            else:
                # Find last fitting blank
                blank_pos = value.rfind(u' ', 0, avl_len)
                if blank_pos < 0:
                    # We cannot split at a blank -> start a new line
                    mof.append(new_line)
                    line_pos = indent
                    avl_len = maxline - indent - quote_len

        # Check whether the entire string fits (that is a last line, then)
        if len(value) <= avl_len - end_space:
            if quote_char:
                mof.append(quote_char)
            mof.append(value)
            if quote_char:
                mof.append(quote_char)
            line_pos += quote_len + len(value)
            break

        # Split the string and output the next part
        split_pos = value.rfind(u' ', 0, avl_len)
        if split_pos < 0:
            # We have to split within a word
            split_pos = avl_len - 1
        part_value = value[0:split_pos + 1]
        value = value[split_pos + 1:]
        if quote_char:
            mof.append(quote_char)
        mof.append(part_value)
        if quote_char:
            mof.append(quote_char)
        line_pos += quote_len + len(part_value)

        if value == u'':
            break

        # A safety check for endless loops
        assert value != saved_value, \
            "Endless loop in _mofstr() with state: " \
            "mof_str={0}, value={1}, avl_len={2}, end_space={3}, " \
            "split_pos={4}". \
            format(u''.join(mof), value, avl_len, end_space, split_pos)

    mof_str = u''.join(mof)
    return mof_str, line_pos


def cimvalue_to_fmtd_string(value, type, indent=0,
                            maxline=DEFAULT_MAX_CELL_WIDTH,
                            line_pos=0, end_space=0, avoid_splits=False,
                            valuemapping=None, quote_strings=True):
    # pylint: disable=redefined-builtin
    """
    Return a MOF string representing a CIM-typed value (scalar or array).

    In case of an array, the array items are separated by comma, but the
    surrounding curly braces are not added.

    In case a value mapping is provided, each value is followed by the
    Values qualifier string in parenthesis. For example, "4" may become
    "4 (Enabled)".

    Parameters:

      value (CIM-typed value or list of CIM-typed values): The value.

      indent (:term:`integer`): Number of spaces to indent any new lines that
        are generated.

      maxline (:term:`integer`): Maximum line length for the generated MOF.

      line_pos (:term:`integer`): Length of content already on the current
        line.

      end_space (:term:`integer`): Length of space to be left free on the last
        line.

      avoid_splits (bool): Avoid splits at the price of starting a new line
        instead of using the current line.

      valuemapping (:class:`pywbem.ValueMapping`): None or a value mapping
        defining a string for the integer-typed property value(s).

      quote_strings (bool):
        If True, surround string values and their folded components with
        quotes. If False, do not surround strings and their components
        with quotes.

    Returns:

      tuple of
        * :term:`unicode string`: MOF string.
        * new line_pos
    """

    if isinstance(value, list):

        mof = []

        for i, v in enumerate(value):

            if i > 0:
                # Assume comma and space as separator
                line_pos += 2

            val_str, line_pos = _scalar_value_tomof(
                v, type, indent, maxline, line_pos, end_space + 2, avoid_splits,
                quote_strings=quote_strings)
            if valuemapping:
                val_str = "{} ({})".format(val_str, valuemapping.tovalues(v))

            if i > 0:
                # Add the actual separator
                mof.append(u',')
                if val_str[0] != '\n':
                    mof.append(u' ')
                else:
                    # Adjust by the space we did not need
                    line_pos -= 1

            mof.append(val_str)

        mof_str = u''.join(mof)

    else:
        mof_str, line_pos = _scalar_value_tomof(
            value, type, indent, maxline, line_pos, end_space, avoid_splits,
            quote_strings=quote_strings)
        if valuemapping:
            mof_str = "{} ({})".format(mof_str, valuemapping.tovalues(value))
    return mof_str, line_pos
