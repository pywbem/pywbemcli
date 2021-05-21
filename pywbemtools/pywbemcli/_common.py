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
Common Functions applicable across multiple components of pywbemcli
"""

from __future__ import absolute_import, print_function, unicode_literals

import fnmatch
import re
try:
    from collections.abc import Sequence
except ImportError:
    from collections import Sequence

import six
import click
from nocaselist import NocaseList
from toposort import toposort_flatten

from pywbem import CIMInstanceName, CIMInstance, CIMClass, \
    CIMQualifierDeclaration, CIMProperty, CIMClassName, \
    cimvalue, Error, CIMInt, CIMFloat, CIMDateTime
from pywbem._nocasedict import NocaseDict

# Same as in pwbem.cimtypes.py
if six.PY2:
    # pylint: disable=invalid-name,undefined-variable
    _Longint = long  # noqa: F821
else:
    # pylint: disable=invalid-name
    _Longint = int

from ._cimvalueformatter import cimvalue_to_fmtd_string
from .._output_formatting import DEFAULT_MAX_CELL_WIDTH
from .._utils import ensure_unicode, to_unicode


######################################################################
#
#  General common functions
#
######################################################################


def resolve_propertylist(propertylist):
    """
    Resolve property list received from click options.  Click options produces
    an empty list when there is no property list.

    Pywbem requires None when there is no propertylist

    Further, property lists can be input as a comma separated list so this
    function also splits any string with embedded commas.

    Parameters:

      propertylist (list of :term:`string` or None):
        Each item in list may be a single property name or a collection of
        property names separated by commas.

    Returns:
        list of property names resulting from parsing input or empty list
        or None
    """
    # If no property list, return None which means all properties
    if not propertylist:
        return None

    # If propertylist is a single empty string, set to empty list.
    if len(propertylist) == 1 and not propertylist[0]:
        propertylist = []

    # expand any comma separated entries in the list
    else:
        pl = []
        for item in propertylist:
            if ',' in item:
                pl.extend(item.split(','))
            else:
                pl.append(item)
        propertylist = pl

    return propertylist


######################################################################
#
#  Functions to select from console
#
######################################################################


def pick_one_from_list(context, options, title):
    """
    Interactive component that displays a set of options (strings) and asks
    the user to select one.  Returns the item and index of the selected string.

    If there is only a single item in the options, simply return that choice
    without user intervention.

    Parameters:
      options:
        List of strings from which one will is to be selected

      title (:term:`string`):
        Title to display before selection

    Retries until either integer within range of options list is input
    or user enter no value. Ctrl-C ends even the REPL.

    Returns:
      Selected item from options_list

    Raises:
      ValueError if Ctrl-c input from console.
    """

    # If there is only a single choice, return that choice.
    if len(options) == 1:
        return options[0]

    # Issue list of choices and prompt for user choice of index
    if context:
        context.spinner_stop()

    click.echo(title)
    for index, str_ in enumerate(options):
        click.echo('{}: {}'.format(index, str_))
    max_option = len(options) - 1
    selection = None
    msg = 'Input integer between 0 and {} or Ctrl-C to exit selection' \
        .format(max_option)

    # Loop for valid user choice until valid choice made or selection aborted
    # by user
    while True:
        try:
            selection_txt = click.prompt(msg)
            selection = int(selection_txt)
            if 0 <= selection <= max_option:
                if context:
                    context.spinner_start()
                return options[selection]
        except ValueError:  # This causes the retry of the request
            pass
        except KeyboardInterrupt:
            raise click.ClickException("Pick Aborted. CTRL-C")
        except Exception as ex:
            raise click.ClickException(
                'Selection exception: {} Command Aborted'.format(ex))
        click.echo('"{}" Invalid response {}'.format(selection_txt, msg))


def pick_instance(context, objectname, namespace=None):
    """
    Display list of instances names from provided classname to console and user
    selects one. Returns the selected instancename.

    Parameters:

      context:
        Current click context or None

      classname:
        Classname to use to get instance names from server

    Returns:
        instancename selected or None if there are no instances to pick

    Raises:
        ClickException if user choses to terminate the selection process
    """
    conn = context.pywbem_server.conn
    if not is_classname(objectname):
        raise click.ClickException('{} must be a classname'.format(objectname))
    instance_names = conn.PyWbemcliEnumerateInstancePaths(objectname,
                                                          namespace)

    if not instance_names:
        click.echo('No instance paths found for {}'.format(objectname))
        return None

    try:
        return pick_one_from_list(context, sort_cimobjects(instance_names),
                                  'Pick Instance name to process')
    except Exception as ex:
        raise click.ClickException('Command Aborted. Exception {}'.format(ex))


def pick_multiple_from_list(context, options, title):
    """
    Interactive component that displays a set of options (strings) and asks
    the user to select multiple entries from that list.  Returns a list of
    the items selected.

    Retries until either integer within range of options list is input
    or user enter no value. Ctrl-C ends even the REPL.

    Parameters:
      context:
        If not None, the ContextObj which is used to stop and start the
        spinner.
      options:
        List of strings to select

      title:
        Title to display before selection

    Returns:
      list of index of selected items

    Raises:
      ValueError if Ctrl-c input from console.
    """

    if context:
        context.spinner_stop()

    click.echo(title)
    index = -1
    for str_ in options:
        index += 1
        click.echo('{}: {}'.format(index, str_))
    selection = None
    selection_list = []
    msg = 'Select entry by index or hit enter to end selection>'
    while True:
        try:
            selection_txt = click.prompt(msg)
            if not selection_txt:
                if context:
                    context.spinner_start()
                return selection_list

            selection = int(selection_txt)
            if 0 <= selection <= index:
                selection_list.append(options[selection])
            continue
        except ValueError:
            pass
        except KeyboardInterrupt:
            raise ValueError
        click.echo('{} Invalid. Input integer between 0 and {}; hit enter to '
                   'stop selection.'.format(selection, index))


def is_classname(astring):
    """
    Test if the a string input is a classname or contains instance name
    components.  The existence of a period at the end of the name component
    determines if it is a class name or instance name.

    Returns:
        True if classname. Otherwise it returns False
    """
    assert isinstance(astring, six.string_types)
    return not re.match(r'[a-zA_Z0-9_].*\.', astring)


def filter_namelist(pattern, name_list, ignore_case=True):
    """
    Filter out names in name_list that do not match glob pattern compiled
    as regex.

    The regex is defined as IGNORECASE and anchored.

    Note that the regex may define a subset of the name string.  Thus,  regex:
        - CIM* matches any name that starts with CIM
        - CIM_abc* matches any name that starts with CIM_abc
        - CIM_ABC matches only the name CIM_ABC.
        - *ABC matches any name that includes ABC

    Parameters:

      pattern (:term:`string`):
        Python glob pattern to match.

      name_list:
        List of strings to be matched.

      ignore_case (bool):
        If True, do case-insensitive match. Default = True

    Returns:
        List of names that match.

    Raises:
        click.ClickException for regex compile error
    """

    flags = re.IGNORECASE if ignore_case else None
    # compile the regex since it used multiple times
    regex = None
    try:
        # Convert the glob input to regex.
        regex = fnmatch.translate(pattern)
        compiled_regex = re.compile(regex, flags)

    except Exception as ex:
        raise click.ClickException('Regex compile error. Regex={}. Er: {}: {}'
                                   .format(regex, ex.__class__.__name__, ex))

    new_list = [n for n in name_list for m in [compiled_regex.match(n)] if m]

    return new_list


def verify_operation(txt, msg=None):
    """
    Issue click confirm request and return result.  If msg is none and
    confirm response is n, output msg.

    Parameters:

      txt (:term:`string`):
        String that is prefixed to the prompt text and defines the
        verification request.

      msg (:class:`py:bool`):
        Optional parameter that if True causes an abort msg on the console.

    Returns:
        (:class:`py:bool`) where true corresponds to 'y' prompt response
    """
    if click.confirm(txt):
        return True
    if msg:
        click.echo('Request aborted')
    return False


def to_wbem_uri_folded(path, format='standard', max_len=15):
    # pylint: disable=redefined-builtin
    """
    Return the (untyped) WBEM URI string of this CIM instance path.
    This method modifies the pywbem:CIMInstanceName.to_wbem_uri method
    to return a reformatted string where components are on
    separate lines if the length is longer than the max_len argument.

    See :meth:`pywbem.CIMInstanceName.to_wbem_uri` for detailed
    information. This method was derived from
    :meth:`pywbem.CIMInstanceName.to_wbem_uri`

    Parameters:

      path (:class:`CIMInstanceName`):
        The instance name to convert to a wbem uri and fold based on
        the max_len parameter

      format  (:term:`string`): Format for the generated WBEM URI string
        using one of the formats defined in
        :meth:`pywbem.CIMInstanceName.to_wbem_uri`

      max_len (:term:`integer`):
        Maximum length of the resulting URI before it is folded into
        multiple lines.

    Returns:

      :term:`unicode string`: Untyped WBEM URI of the CIM instance path,
      in the specified format.

    Raises:

      TypeError: Invalid type in keybindings
      ValueError: Invalid format
    """

    path_str = path.to_wbem_uri(format=format)
    if len(path_str) <= max_len:
        return path_str

    # Otherwise recreate the wbem uri and  fold the
    # keybindings. This folds the keybindings as they are mapped back to
    # strings. Note that this recreates the much of the pywbem wbemuri method
    # except that it folds keybindings.

    ret = []

    def case(astring):
        """Return the string in the correct lexical case for the format."""
        if format == 'canonical':
            astring = astring.lower()
        return astring

    def case_sorted(keys):
        """Return the keys in the correct order for the format."""
        if format == 'canonical':
            case_keys = [case(k) for k in keys]
            keys = sorted(case_keys)
        return keys

    if format not in ('standard', 'canonical', 'cimobject', 'historical'):
        raise ValueError('Invalid format argument: {0}'.format(format))

    if path.host is not None and format != 'cimobject':
        # The CIMObject format assumes there is no host component
        ret.append('//')
        ret.append(case(path.host))

    if path.host is not None or format not in ('cimobject', 'historical'):
        ret.append('/')

    if path.namespace is not None:
        ret.append(case(path.namespace))

    if path.namespace is not None or format != 'historical':
        ret.append(':')

    ret.append(case(path.classname))

    ret.append('.\n')

    for key in case_sorted(six.iterkeys(path.keybindings)):
        value = path.keybindings[key]

        ret.append(key)
        ret.append('=')

        if isinstance(value, six.binary_type):
            value = to_unicode(value)

        if isinstance(value, six.text_type):
            # string, char16
            ret.append('"')
            ret.append(value.
                       replace('\\', '\\\\').
                       replace('"', '\\"'))
            ret.append('"')
        elif isinstance(value, bool):
            # boolean
            # Note that in Python a bool is an int, so test for bool first
            ret.append(str(value).upper())
        elif isinstance(value, (CIMFloat, float)):
            # realNN
            # Since Python 2.7 and Python 3.1, repr() prints float numbers
            # with the shortest representation that does not change its
            # value. When needed, it shows up to 17 significant digits,
            # which is the precision needed to round-trip double precision
            # IEE-754 floating point numbers between decimal and binary
            # without loss.
            ret.append(repr(value))
        elif isinstance(value, (CIMInt, int, _Longint)):
            # intNN
            ret.append(str(value))
        elif isinstance(value, CIMInstanceName):
            # reference
            ret.append('"')
            ret.append(value.to_wbem_uri(format=format).
                       replace('\\', '\\\\').
                       replace('"', '\\"'))
            ret.append('"')
        elif isinstance(value, CIMDateTime):
            # datetime
            ret.append('"')
            ret.append(str(value))
            ret.append('"')
        else:
            raise TypeError(
                "Invalid type {0} in keybinding value: {1}={2}"
                .format(type(value), key, value))
        ret.append(',\n')

    del ret[-1]

    return ensure_unicode(''.join(ret))


def parse_wbemuri_str(wbemuri_str, namespace=None):
    """
    Parse a string that is a wbemuri into a CIMInstanceName object.  This method
    parses a string consistent with a wbemuri into a CIMInstanceName object.

    If the wbem_uri includes a namespace that is parsed also.  If both
    the namespace optional parameter exists and the wbemuri_str parameter
    includes a namespace (and they are not the same), an exception is returned.

    Returns:
        CIMInstanceName instance object

    Raises:
        ClickException: if the input wbemuri_str is an invalid wbemuri.
    """
    try:
        instance_name = CIMInstanceName.from_wbem_uri(wbemuri_str)
        if instance_name.namespace and namespace:
            if instance_name.namespace != namespace:
                raise click.ClickException('Conflicting namespaces between '
                                           'wbemuri {} and option {}'
                                           .format(instance_name.namespace,
                                                   namespace))
        elif instance_name.namespace is None and namespace:
            instance_name.namespace = namespace

        return instance_name
    except ValueError as ve:
        raise click.ClickException('Invalid wbem uri input {}. Error {}'
                                   .format(wbemuri_str, ve))


def str_2_bool(value):
    """
    Convert the value input to boolean based on text or
    raise ValueError if strings are not 'true' or 'false'.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, six.string_types):
        if value.lower() == 'true':
            return True
        if value.lower() == 'false':
            return False
    raise ValueError('Invalid boolean value: "{}"'.format(value))


def create_cimvalue(cim_type, value_str, is_array):
    """
    Build a cim value of the type in cim_type and the information in value_str
    or fail with an exception if the value_str cannot be parsed into a
    CIMValue or list of CIMValue elements.

    Parameters:
      cim_type (:term:`string`):
        CIMType for this value. The CIM data type name for the CIM object.
        See :ref:`CIM data types` for valid type names.

      value_str (:term:`string`):
        String defining the input to be parsed.

      is_array (:class:`py:bool`):
        The value_str is to be treated as a comma separated set of values.

    Return:
        is_array == False. Returns a single CIMValue
        is_array == True. Returns a list of CIMValues

    Raises:
        ValueError if the value_str cannot be parsed consistent with
        the cim_type and is_array attributes of the call.
    """

    if value_str is None:
        return None

    if not is_array:
        # cimvalue does not handle strings for bool
        if cim_type == 'boolean':
            value_str = str_2_bool(value_str)
        cim_value = cimvalue(value_str, cim_type)
    else:
        cim_value = []
        values_list = split_array_value(value_str, ',')
        for val in values_list:
            if cim_type == 'boolean':
                val = str_2_bool(val)
            cim_value.append(cimvalue(val, cim_type))
    return cim_value


def create_cimproperty(cim_type, is_array, name, value_str):
    """
    Create and return a CIMProperty from the input parameters and the
    information in cim_class.

    Parameters:

      cim_type (:term:`string`):
        CIM type of the property

      is_array (bool):
        Boolean indicating that property is an array

      name (:term:`string`):
        Name of the property to be constructed

      value_str (:term:`string`):
        String form for the value to be inserted.

    Returns:
        CIMProperty with name defined by name and CIMValue corresponding to
        value_str and property information from the class

    Raises:
        ValueError if value_str, cim_type and is_array mismatch.
    """
    cim_value = create_cimvalue(cim_type, value_str, is_array)

    return CIMProperty(name, cim_value, type=cim_type, is_array=is_array)


def create_ciminstance(cim_class, kv_properties):
    """
    Create a CIMInstance object from the input parameters.

    Parameters:

      cim_class (CIMClass):
        The class from which the CIMInstance is to be created

      kv_properties (tuple):
        A tuple of "name=value" strings representing the properties and their
        values that are to be constructed for the instance. Required

    Returns:
        CIMInstance

    Raises:
        click.ClickException if Property name not found in class or if mismatch
          of property type in class vs value component of kv pair
    """
    properties = []
    for kv_property in kv_properties:
        name, value_str = parse_kv_pair(kv_property)
        try:
            cl_prop = cim_class.properties[name]
        except KeyError:
            raise click.ClickException('Property name "{}" not in class "{}".'
                                       .format(name, cim_class.classname))

        try:
            prop = create_cimproperty(cl_prop.type,
                                      cl_prop.is_array,
                                      name,
                                      value_str)
            properties.append((name, prop))
        except ValueError as ex:
            raise click.ClickException("Type mismatch property '{}' between "
                                       "expected type='{}', array={} and input "
                                       "value='{}'. Exception: {}"
                                       .format(name, cl_prop.type,
                                               cl_prop.is_array,
                                               value_str, ex))

    new_inst = CIMInstance(cim_class.classname, properties=properties)

    return new_inst


def compare_obj(obj1, obj2, msg):
    """
    Compare two objects and display error if different.  Returns True if
    match or False if different
    """
    if obj1 != obj2:
        click.echo('Obj Compare {}: compare mismatch:\n{!r}\n{!r}'
                   .format(msg, obj1, obj2))
        return False
    return True


def compare_instances(inst1, inst2):
    """
    Compare two instances. If they do not match, compare the details to
    find differnes and report the differences. Report the differences
    """
    if inst1 != inst2:
        if not compare_obj(inst1.classname, inst2.classname, "classname"):
            return False
        if not compare_obj(inst1.path, inst2.path, "path"):
            return False
        if not compare_obj(inst1.qualifiers, inst2.qualifiers, "qualifiers"):
            return False
        if inst1.properties == inst2.properties:
            return True
        if len(inst1.properties) != len(inst2.properties):
            click.echo('Different number of properties {} vs {}\n{}\n{}'
                       .format(len(inst1.properties), len(inst2.properties),
                               inst1.keys(), inst2.keys()))
            return False
        keys1 = set(inst1.keys())
        keys2 = set(inst2.keys())
        if keys1 != keys2:
            diff = keys1.symmetric_difference(keys2)
            click.echo('Property Name differences {}'.format(diff))
            return False

        for n1, v1 in six.iteritems(inst1):
            if v1 != inst2[n1]:
                msg = 'property ' + n1
                if not compare_obj(inst1.get(n1), inst2.get(n1), msg):
                    return False
    return True


def parse_kv_pair(pair):
    """
    Parse a single "KEY=VALUE" string and return a tuple (key, value).

    The parsing assumes that KEY does not include '=', which is always the case
    for CIM names. VALUE may contain '=' characters, which are retained.

    If 'VALUE' or '=VALUE' are missing, value is returned as None.
    """
    name, value = pair.partition("=")[::2]

    # if VALUE is missing, return it as None.
    if not value:
        value = None

    return name, value


def split_array_value(astring, delimiter):
    """Simple split of a string based on a delimiter"""

    rslt = split_str_w_esc(astring, delimiter)
    return rslt


def split_str_w_esc(astring, delimiter, escape='\\'):
    """
    Split string based on delimiter defined in call and the escape character \\
    To escape use of the delimiter in the strings. Delimiter may be multi
    character.
    Returns list of elements split from the input str
    """
    ret = []
    current_element = []
    iterator = iter(astring)
    for ch in iterator:
        if ch == escape:
            try:
                next_character = next(iterator)
                # Do not copy escape character if intended to escape either the
                # delimiter or the escape character itself. Copy the escape
                # character if it is not in use to escape one of these
                # characters.
                if next_character not in [delimiter, escape]:
                    current_element.append(escape)
                current_element.append(next_character)
            except StopIteration:
                current_element.append(escape)
        elif ch == delimiter:
            # split! (add current to the list and reset it)
            ret.append(''.join(current_element))
            current_element = []
        else:
            current_element.append(ch)
    ret.append(''.join(current_element))
    return ret


def process_invokemethod(context, objectname, methodname, namespace,
                         parameters):
    # pylint: disable=line-too-long
    """
    Process the parameters for invokemethod at either the class or instance
    level and execute the invokemethod.

    Parameters:

      objectname (:class:`~pywbem.CIMClassName` or :class:`~pywbem.CIMInstanceName`)  # noqa: E501
        The objectname (class or instance) that is the invokemethod
        target. The namespace must have been inserted into the objectname
        before calling this method

      methodname (:term:`string`):
        The name of the method to be executed

      namespace (:term:`string`):
        String defining the current namespace used by the command or None
        if the default namespace is to be used

      parameters ():
        The input parameters to be applied to the InvokeMethod


    """  # pylint: enable=line-too-long

    def create_params(classname, cim_method, kv_params):
        """
        Create parameter values from the input arguments and class.

        Parameters:

          cim_method (CIMMethod):
            CIM Method that is the template for the parameters.  It is used to
            evaluate the kv_params and generate corresponding CIMParameter
            objects to be passed to the InvokeMethod
        """
        params = []
        for p in kv_params:
            name, value_str = parse_kv_pair(p)
            if name not in cim_method.parameters:
                raise click.ClickException(
                    "Method {} of class {} does not have a parameter {}".
                    format(cim_method.name, classname, name))

            if name in params:
                raise click.ClickException(
                    "Method parameter {} specified multiple times".
                    format(name))

            cl_param = cim_method.parameters[name]
            is_array = cl_param.is_array

            cim_value = create_cimvalue(cl_param.type, value_str, is_array)
            params.append((name, cim_value))
        return params

    assert isinstance(objectname, (CIMClassName, CIMInstanceName))
    conn = context.pywbem_server.conn
    classname = objectname.classname

    # if this is a string convert to a CIMClassname
    if isinstance(objectname, six.string_types):
        objectname = CIMClassName(objectname)

    if namespace:
        objectname.namespace = namespace

    cim_class = conn.GetClass(classname, namespace=namespace, LocalOnly=False)

    cim_methods = cim_class.methods
    if methodname not in cim_methods:
        raise click.ClickException(
            "Class {} does not have a method {}"
            .format(classname, methodname))
    cim_method = cim_methods[methodname]

    params = create_params(classname, cim_method, parameters)

    rtn = conn.InvokeMethod(methodname, objectname, params)

    # Output results, both ReturnValue and all output parameters
    click.echo('ReturnValue={}'.format(rtn[0]))

    if rtn[1]:
        cl_params = cim_method.parameters
        rtn_params = rtn[1]
        for pname, pvalue in rtn_params.items():
            ptype = cl_params[pname].type if pname in cl_params else None
            val = cimvalue_to_fmtd_string(
                pvalue, ptype, maxline=DEFAULT_MAX_CELL_WIDTH,
                avoid_splits=False)
            click.echo('{}={}'.format(pname, val[0]))


def sort_cimobjects(cim_objects):
    """
    Return a sorted list of the input objects.

    The returned list is always a new list and its items are the original input
    objects.

    The following input object types are supported, and their sort key is:

    * string: Sorted by string value (case sensitively). This case covers the
      result of 'class enumerate'.

    * CIMClass: Sorted by class name (case sensitively).

    * CIMClassName, CIMInstanceName: Sorted by its canonical WBEM URI string.
      This makes the sort case insensitive.

    * CIMInstance: Must have the path set. Sorted by the canonical WBEM URI
      string of its instance path. This makes the sort case insensitive.

    * CIMQualifierDeclaration: Sorted by qualifier name (case sensitively).

    * tuple(CIMClassName, CIMClass): Sorted by the canonical WBEM URI
      string of the CIMClassName object. This makes the sort case insensitive.
      This case covers the result of 'class references/associators'.

    Parameters:

      cim_objects (Sequence): Objects to be sorted.

    Returns:
        A new list of the original input objects, sorted as defined above.

    Raises:
        TypeError: Invalid type for input parameter 'cim_objects'.
        ValueError: CIMInstance object in sort list has no 'path' set.
    """
    assert isinstance(cim_objects, Sequence)

    if not cim_objects:
        return []

    tst_obj = cim_objects[0]

    # This case covers result of 'class enumerate':
    if isinstance(tst_obj, six.string_types):
        return sorted(cim_objects)

    if isinstance(tst_obj, CIMClass):
        return sorted(cim_objects,
                      key=lambda obj: obj.classname)

    if isinstance(tst_obj, (CIMClassName, CIMInstanceName)):
        return sorted(cim_objects,
                      key=lambda obj: obj.to_wbem_uri(format="canonical"))

    if isinstance(tst_obj, CIMInstance):
        try:
            return sorted(
                cim_objects,
                key=lambda obj: obj.path.to_wbem_uri(format="canonical"))
        except AttributeError as exc:
            new_exc = ValueError(
                "CIMInstance object in sort list has no 'path' set: {}".
                format(exc))
            new_exc.__cause__ = None
            raise new_exc

    if isinstance(tst_obj, CIMQualifierDeclaration):
        return sorted(cim_objects,
                      key=lambda obj: obj.name)

    # This case covers result of 'class references/associators':
    if isinstance(tst_obj, tuple):
        if not isinstance(tst_obj[0], CIMClassName) or \
                not isinstance(tst_obj[1], CIMClass):
            raise TypeError("Items of type tuple ({}, {}) cannot be sorted".
                            format(type(tst_obj[0]), type(tst_obj[1])))
        return sorted(cim_objects,
                      key=lambda tup: tup[0].to_wbem_uri(format="canonical"))

    raise TypeError("Items of type {} cannot be sorted".format(type(tst_obj)))


def get_leafclass_names(classes):
    """
    Get the leaf classes of the classes that are present in the
    input list classes

      Parameters:
        classes: list of :class:`pywbem:CIMClass`

      Returns
        NocaseList of :term:`unicode string` with the names of all classes
        that do not have a subclass

    """
    # Build dictionary of superclassname: classnames. This can be used to
    # find subclasses of any class in the dictionary.
    classname_dict = {}
    for c in classes:
        if c.classname not in classname_dict:
            classname_dict[c.classname] = []
        if c.superclass:
            if c.superclass in classname_dict:
                classname_dict[c.superclass].append(c.classname)
            else:
                classname_dict[c.superclass] = [c.classname]

    # get list of all classnames with no value (i.e. no subclasses)
    rtn_list = [key for key, value in six.iteritems(classname_dict)
                if not value]
    return NocaseList(rtn_list)


def get_subclass_names(classes, classname=None, deep_inheritance=None):
    """
    Get class names that are subclasses of classname, including indirect
    subclasses of the classname input parameter from a list of CIM Classes.

    The input classname is NOT included in the returned list.

    Note: The classes list MUST include all subclasses to any class
    that is the list (i.e what is returned by an enumerate classes) but need
    not include the top level classes(those with with c.superclass == None)

    Parameters:
      classname (:term:`string`):
        The name of the CIM class for which subclass names will
        be retrieved. If None, retrieval starts at the root of
        the class hierarchy. Classes that have superclass None or have
        a superclass not in the list of classes

      classes (:class:`~pywbem_mock.BaseObjectStore):
       A list of CIM classes for which the subclass of a member is to
       be returned.

      deep_inheritance (:class:`py:bool`):
        If True, the complete set of subclasses found in the classes list
        is returned.  If not True, only the direct subclasses list is returned.

    Returns:
      NocaseList of :term:`unicode string` with the names of all subclasses of
      `classname`.  returns empty list if classname is not in the list or their
      are no subclasses.

    Exceptions: ValueError if classname not in classes
    """

    assert isinstance(classname, six.string_types)

    # Build dictionary of superclassname: classnames
    classname_dict = NocaseDict()
    for c in classes:
        if c.classname not in classname_dict:
            classname_dict[c.classname] = []
        if c.superclass:
            if c.superclass in classname_dict:
                classname_dict[c.superclass].append(c.classname)
            else:
                classname_dict[c.superclass] = [c.classname]

    if classname not in classname_dict:
        raise ValueError("Classname {} not found in classes".format(classname))

    # Recurse the classname_dict hierarchy to get subclass names
    rtn_classnames = classname_dict[classname]
    if deep_inheritance:
        if rtn_classnames:
            subclass_names = rtn_classnames
            while True:
                subclass_names_rtn = []
                for cln in subclass_names:
                    subclass_names_rtn.extend(classname_dict[cln])
                if subclass_names_rtn:
                    rtn_classnames.extend(subclass_names_rtn)
                    subclass_names = subclass_names_rtn
                else:
                    break
    return NocaseList(rtn_classnames)


def shorten_path_str(path, replacements, fullpath):
    """
    Create a short-form path str from the input CIMInstanceName with selected
    components shortened to just a single known character.  This allows
    modifying the path string to replace selected key/value pairs with a single
    character. Thus where the original string is very long and contains
    repeated key bindings (ex. CreationClassName) we can shorten the path
    string by reducing selected key/value pairs to just ~

    Parameters:

      path (:class:`CIMInstanceName`):
        CIMInstanceName object defining instance name to shorten

      replacements:
        Dictionary of the replacements containing a key names and key
        values to be replaced. If the key value is None, they name alone
        causes the replacement. Otherwise, both the name and value must
        match.

      fullpath (:class:`py:bool`):
        If True Return complete path using to_wbem_rul. Otherwise, shorten
        the path by replacing keys defined by the replacements dictionary.
        shorten the path, otherwise simply convert to string. Othewise

    Returns:
        String representation of the path.
    """

    if fullpath:
        # Just build the full path string
        name_str = path.to_wbem_uri()

    else:
        # Shorten path based on key definitons in replacements
        kbs = path.keybindings
        repl_list = []
        magicvalue = 9999123999918
        for k, v in kbs.items():
            for key, value in replacements.items():
                if k.lower() == key.lower():
                    if value is None or v == value:
                        repl_list.append((key, value))
                        # Set the value to a known value for the replacement
                        kbs[key] = magicvalue
        path.keybindings = kbs
        name_str = path.to_wbem_uri()
        # replace each key binding in repl_list with ~ char
        for key, value in repl_list:
            name_str = name_str.replace("{}={}".format(key, magicvalue), "~", 1)

    return name_str


def pywbem_error_exception(exc, intro=None):
    """
    Return the standard click exception for a pywbem Error exception.  These
    exceptions do not cause interactive mode failure but display the exception
    class and its str value and return to the repl mode.

    Parameters:

      exc (Exception): The pywbem Error exception.

      intro (string): An additional message used as introduction for the
        resulting click exception message. This message usually states what
        cannot be done due to the error.

    Returns:
        click.ClickException: Click exception for the pywbem Error exception.
    """
    if intro:
        msg = "{}: {}: {}".format(intro, exc.__class__.__name__, exc)
    else:
        msg = "{}: {}".format(exc.__class__.__name__, exc)
    return click.ClickException(msg)


def dependent_classnames(cls_obj):
    """
    Determine the CIM classes the specified CIM class depends upon, based uopn
    the class declaration in the CIMClass object. This function operates solely
    on the provided CIMClass object and does not communicate with the WBEM
    server.

    The following types of dependencies are considered:
    * Superclass
    * Referenced classes (in properties and method parameters)
    * Embedded classes specified with the EmbeddedInstance qualifier (in
      properties, method return values and method parameters)

    The following types of dependencies are not considered:
    * Embedded classes specified with the EmbeddedObject qualifier (in
      properties, method return values and method parameters)
    * Classes specified in the Deprecated qualifier
    * Classes specified in the ModelCorrespondence qualifier

    Note that method return types cannot be references even though this is
    permitted in DSP0004 because DSP0200 does not support the representation of
    such method declarations. Therefore, pywbemtools does not check for them.

    Parameters:

      cls_obj (CIMClass): The specified CIM class.

    Returns:

      NocaseList of string: The unique list of class names of the dependent
      classes, in no particular order. It is guaranteed that the specified class
      itself will not be contained in this list (e.g. when it references itself
      in a method parameter).
    """

    def _add(classnames, new_classname):
        """
        Append new_classname to classnames if not yet contained.

        This provides the add() functionality of a case-insensitive set.
        """
        if new_classname not in classnames:
            classnames.append(new_classname)

    dependent_cln_list = NocaseList()
    if cls_obj.superclass:
        _add(dependent_cln_list, cls_obj.superclass)
    for prop in cls_obj.properties.values():
        embinst_qual = prop.qualifiers.get('EmbeddedInstance', None)
        if embinst_qual:
            _add(dependent_cln_list, embinst_qual.value)
        if prop.reference_class:
            _add(dependent_cln_list, prop.reference_class)
    for meth in cls_obj.methods.values():
        embinst_qual = meth.qualifiers.get('EmbeddedInstance', None)
        if embinst_qual:
            _add(dependent_cln_list, embinst_qual.value)
        # No check for method return values that are references, because that
        # cannot be represented in CIM-XML, even though allowed in DSP0004.
        for parm in meth.parameters.values():
            embinst_qual = parm.qualifiers.get('EmbeddedInstance', None)
            if embinst_qual:
                _add(dependent_cln_list, embinst_qual.value)
            if parm.reference_class:
                _add(dependent_cln_list, parm.reference_class)

    try:
        dependent_cln_list.remove(cls_obj.classname)
    except ValueError:
        pass

    return dependent_cln_list


def depending_classnames(classname, namespace, conn):
    """
    Enumerate all CIM classes in the namespace, determine the classes that
    depend on the specified CIM class and return these depending classes as a
    list of class names.

    This function basically inverts the dependencies determined by
    dependent_classnames(). See there for a description of the class
    dependencies that are considered.

    Parameters:

      classname (string): Class name of the specified CIM class.

      namespace (string): Namespace of the specified CIM class.

      conn (WBEMConnection): WBEM server connection to be used.

    Returns:

      NocaseList of string: The class names of the classes that depend on the
      specified class. It is guaranteed that the specified class itself will
      not be contained in this list (e.g. when it references itself in a method
      parameter).

    Raises:
        click.ClickException: For any WBEM operation errors.
    """
    try:
        all_classes = conn.EnumerateClasses(
            namespace=namespace, ClassName=None,
            IncludeQualifiers=True, DeepInheritance=True, LocalOnly=True)
    except Error as exc:
        raise pywbem_error_exception(
            exc, "Cannot enumerate classes in namespace {}".format(namespace))

    depending_cln_list = NocaseList()
    for cls in all_classes:
        dep_classnames = dependent_classnames(cls)
        if classname in dep_classnames:
            if cls.classname not in depending_cln_list:
                depending_cln_list.append(cls.classname)

    return depending_cln_list


def all_classnames_depsorted(namespace, conn):
    """
    Enumerate all CIM classes in the namespace and return them in a
    dependency-sorted order where the classes that depend on other classes are
    placed before the classes they depend upon.

    This allows for example deleting the classes in the order of the returned
    list without creating or failing due to dangling dependencies.

    The class dependencies that are considered for this purpose are described
    in dependent_classnames().

    Parameters:

      namespace (string): CIM namespace to be used.

      conn (WBEMConnection): WBEM server connection to be used.

    Returns:

      NocaseList of string: The class names of all classes in the namespace
        in dependency-sorted order.

    Raises:
        click.ClickException: For any WBEM operation errors.
    """

    try:
        all_classes = conn.EnumerateClasses(
            namespace=namespace, ClassName=None,
            IncludeQualifiers=True, DeepInheritance=True, LocalOnly=True)
    except Error as exc:
        raise pywbem_error_exception(
            exc, "Cannot enumerate classes in namespace {}".format(namespace))

    all_deps = dict()
    for cls in all_classes:
        dep_classnames = dependent_classnames(cls)
        all_deps[cls.classname] = set(dep_classnames)

    # ISSUE #954: Add support for case insensitive sorting.
    flat_cln_iterable = toposort_flatten(all_deps)

    return NocaseList(reversed(flat_cln_iterable))
