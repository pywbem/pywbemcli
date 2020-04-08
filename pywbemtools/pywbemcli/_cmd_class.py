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
Click Command definition for the class command group which includes
commands for get, enumerate, associators, references, find, etc. of the objects
CIMClass on a WBEM server.

NOTE: Commands are ordered in help display by their order in this file.
"""

from __future__ import absolute_import, print_function

import click

from pywbem import Error, CIMClassName, CIMError, CIM_ERR_NOT_FOUND, CIMClass

from .pywbemcli import cli
from ._common import display_cim_objects, filter_namelist, \
    resolve_propertylist, CMD_OPTS_TXT, GENERAL_OPTS_TXT, SUBCMD_HELP_TXT, \
    TABLE_FORMATS, format_table, process_invokemethod, \
    raise_pywbem_error_exception, warning_msg, validate_output_format
from ._common_options import add_options, propertylist_option, \
    names_only_option, include_classorigin_class_option, namespace_option,  \
    summary_option, multiple_namespaces_option, association_filter_option, \
    indication_filter_option, experimental_filter_option, help_option
from ._displaytree import display_class_tree
from ._click_extensions import PywbemcliGroup, PywbemcliCommand


#
#   Common option definitions for class group
#

# NOTE: A number of the options use double-dash as the short form.  In those
# cases, a third definition of the options without the double-dash defines
# the corresponding option name, ex. 'include_qualifiers'. It should be
# defined with underscore and not dash

no_qualifiers_class_option = [              # pylint: disable=invalid-name
    click.option('--nq', '--no-qualifiers', 'no_qualifiers', is_flag=True,
                 default=True,
                 help='Do not include qualifiers in the returned class(es). '
                      'Default: Include qualifiers.')]

deep_inheritance_class_option = [              # pylint: disable=invalid-name
    click.option('--di', '--deep-inheritance', 'deep_inheritance', is_flag=True,
                 default=False,
                 help='Include the complete subclass hierarchy of the '
                      'requested classes in the result set. '
                      'Default: Do not include subclasses.')]

local_only_class_option = [              # pylint: disable=invalid-name
    click.option('--lo', '--local-only', 'local_only', is_flag=True,
                 default=False,
                 help='Do not include superclass properties and methods in '
                      'the returned class(es). '
                      'Default: Include superclass properties and methods.')]


##########################################################################
#
#   Click command group and command definitions
#   These decorated functions implement the commands, arguments, and
#   options for the top-level class command group
#
###########################################################################

@cli.group('class', cls=PywbemcliGroup, options_metavar=GENERAL_OPTS_TXT,
           subcommand_metavar=SUBCMD_HELP_TXT)
@add_options(help_option)
def class_group():
    """
    Command group for CIM classes.

    This command group defines commands to inspect classes, invoke
    methods on classes, delete classes.

    Creation and modification of classes is not currently supported.

    In addition to the command-specific options shown in this help text, the
    general options (see 'pywbemcli --help') can also be specified before the
    'class' keyword.
    """
    pass  # pylint: disable=unnecessary-pass


@class_group.command('enumerate', cls=PywbemcliCommand,
                     options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=False)
@add_options(deep_inheritance_class_option)
@add_options(local_only_class_option)
@add_options(no_qualifiers_class_option)
@add_options(include_classorigin_class_option)
@add_options(names_only_option)
@add_options(namespace_option)
@add_options(summary_option)
@add_options(association_filter_option)
@add_options(indication_filter_option)
@add_options(experimental_filter_option)
@add_options(help_option)
@click.pass_obj
def class_enumerate(context, classname, **options):
    """
    List top classes or subclasses of a class in a namespace.

    Enumerate CIM classes starting either at the top of the class hierarchy
    in the specified CIM namespace (--namespace option), or at the specified
    class (CLASSNAME argument) in the specified namespace. If no namespace was
    specified, the default namespace of the connection is used.

    The --local-only, --include-classorigin, and --no-qualifiers options
    determine which parts are included in each retrieved class.

    The --deep-inheritance option defines whether or not the complete subclass
    hierarchy of the classes is retrieved.

    The --names-only option can be used to show only the class paths.

    In the output, the classes and class paths will be formatted as defined
    by the --output-format general option. Table formats on classes will be
    replaced with MOF format.

    Examples:

      pywbemcli -n myconn class enumerate -n interop

      pywbemcli -n myconn class enumerate CIM_Foo -n interop
    """
    context.execute_cmd(lambda: cmd_class_enumerate(context, classname,
                                                    options))


@class_group.command('get', cls=PywbemcliCommand, options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@add_options(local_only_class_option)
@add_options(no_qualifiers_class_option)
@add_options(include_classorigin_class_option)
@add_options(propertylist_option)
@add_options(namespace_option)
@add_options(help_option)
@click.pass_obj
def class_get(context, classname, **options):
    """
    Get a class.

    Get a CIM class (CLASSNAME argument) in a CIM namespace (--namespace
    option). If no namespace was specified, the default namespace of the
    connection is used.

    The --local-only, --include-classorigin, --no-qualifiers, and
    --propertylist options determine which parts are included in each retrieved
    class.

    In the output, the class will be formatted as defined by the
    --output-format general option. Table formats are replaced with MOF
    format.

    Example:

      pywbemcli -n myconn class get CIM_Foo -n interop
    """
    context.execute_cmd(lambda: cmd_class_get(context, classname, options))


@class_group.command('delete', cls=PywbemcliCommand,
                     options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@click.option('-f', '--force', is_flag=True, default=False,
              help='Delete any instances of the class as well. '
                   'Some servers may still reject the class deletion. '
                   'Default: Reject command if the class has any instances.')
@add_options(namespace_option)
@add_options(help_option)
@click.pass_obj
def class_delete(context, classname, **options):
    """
    Delete a class.

    Delete a CIM class (CLASSNAME argument) in a CIM namespace (--namespace
    option). If no namespace was specified, the default namespace of the
    connection is used.

    If the class has subclasses, the command is rejected.

    If the class has instances, the command is rejected, unless the --force
    option was specified, in which case the instances are also deleted.

    WARNING: Deleting classes can cause damage to the server: It can impact
    instance providers and other components in the server. Use this
    command with caution.

    Many WBEM servers may not allow this operation or may severely limit the
    conditions under which a class can be deleted from the server.

    Example:

      pywbemcli -n myconn class delete CIM_Foo -n interop
    """
    context.execute_cmd(lambda: cmd_class_delete(context, classname, options))


@class_group.command('invokemethod', cls=PywbemcliCommand,
                     options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@click.argument('methodname', type=str, metavar='METHODNAME', required=True)
@click.option('-p', '--parameter', type=str, metavar='PARAMETERNAME=VALUE',
              required=False, multiple=True,
              help='Specify a method input parameter with its value. '
                   'May be specified multiple times. '
                   'Default: No input parameters.')
@add_options(namespace_option)
@add_options(help_option)
@click.pass_obj
def class_invokemethod(context, classname, methodname, **options):
    """
    Invoke a method on a class.

    Invoke a static CIM method (METHODNAME argument) on a CIM class (CLASSNAME
    argument) in a CIM namespace (--namespace option), and display the method
    return value and output parameters. If no namespace was specified, the
    default namespace of the connection is used.

    The method input parameters are specified using the --parameter option,
    which may be specified multiple times.

    Pywbemcli retrieves the class definition from the server in order to
    verify that the specified input parameters are consistent with the
    parameter characteristics in the method definition.

    Use the 'instance invokemethod' command to invoke CIM methods on CIM
    instances.

    Example:

      pywbemcli -n myconn class invokemethod CIM_Foo methodx -p p1=9 -p p2=Fred
    """
    context.execute_cmd(lambda: cmd_class_invokemethod(context,
                                                       classname,
                                                       methodname,
                                                       options))


@class_group.command('references', cls=PywbemcliCommand,
                     options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True)
@click.option('--rc', '--result-class', 'result_class', type=str,
              required=False, metavar='CLASSNAME',
              help='Filter the result set by result class name. '
                   'Subclasses of the specified class also match.')
@click.option('-r', '--role', type=str, required=False,
              metavar='PROPERTYNAME',
              help='Filter the result set by source end role name.')
@add_options(no_qualifiers_class_option)
@add_options(include_classorigin_class_option)
@add_options(propertylist_option)
@add_options(names_only_option)
@add_options(namespace_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def class_references(context, classname, **options):
    """
    List the classes referencing a class.

    List the CIM (association) classes that reference the specified class
    (CLASSNAME argument) in the specified CIM namespace
    (--namespace option). If no namespace was specified, the default namespace
    of the connection is used.

    The classes to be retrieved can be filtered by the --role and
    --result-class options.

    The --include-classorigin, --no-qualifiers, and --propertylist options
    determine which parts are included in each retrieved class.

    The --names-only option can be used to show only the class paths.

    In the output, the classes and class paths will be formatted as defined
    by the --output-format general option. Table formats on classes will be
    replaced with MOF format.

    Examples:

      pywbemcli -n myconn class references CIM_Foo -n interop
    """
    context.execute_cmd(lambda: cmd_class_references(context, classname,
                                                     options))


@class_group.command('associators', cls=PywbemcliCommand,
                     options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True)
@click.option('--ac', '--assoc-class', 'assoc_class', type=str, required=False,
              metavar='CLASSNAME',
              help='Filter the result set by association class name. '
                   'Subclasses of the specified class also match.')
@click.option('--rc', '--result-class', 'result_class', type=str,
              required=False, metavar='CLASSNAME',
              help='Filter the result set by result class name. '
                   'Subclasses of the specified class also match.')
@click.option('-r', '--role', type=str, required=False,
              metavar='PROPERTYNAME',
              help='Filter the result set by source end role name.')
@click.option('--rr', '--result-role', 'result_role', type=str, required=False,
              metavar='PROPERTYNAME',
              help='Filter the result set by far end role name.')
@add_options(no_qualifiers_class_option)
@add_options(include_classorigin_class_option)
@add_options(propertylist_option)
@add_options(names_only_option)
@add_options(namespace_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def class_associators(context, classname, **options):
    """
    List the classes associated with a class.

    List the CIM classes that are associated with the specified class
    (CLASSNAME argument) in the specified CIM namespace
    (--namespace option). If no namespace was specified, the default namespace
    of the connection is used.

    The classes to be retrieved can be filtered by the --role, --result-role,
    --assoc-class, and --result-class options.

    The --include-classorigin, --no-qualifiers, and --propertylist options
    determine which parts are included in each retrieved class.

    The --names-only option can be used to show only the class paths.

    In the output, the classes and class paths will be formatted as defined
    by the --output-format general option. Table formats on classes will be
    replaced with MOF format.

    Examples:

      pywbemcli -n myconn class associators CIM_Foo -n interop
    """
    context.execute_cmd(lambda: cmd_class_associators(context, classname,
                                                      options))


@class_group.command('find', cls=PywbemcliCommand, options_metavar=CMD_OPTS_TXT)
@click.argument('classname-glob', type=str, metavar='CLASSNAME-GLOB',
                required=True)
@add_options(multiple_namespaces_option)
@click.option('-s', '--sort', is_flag=True, required=False,
              help='Sort by namespace. Default is to sort by classname')
@add_options(association_filter_option)
@add_options(indication_filter_option)
@add_options(experimental_filter_option)
@add_options(help_option)
@click.pass_obj
def class_find(context, classname_glob, **options):
    """
    List the classes with matching class names on the server.

    Find the CIM classes whose class name matches the specified wildcard
    expression (CLASSNAME-GLOB argument) in all CIM namespaces of the
    WBEM server, or in the specified namespace (--namespace option).

    The CLASSNAME-GLOB argument is a wildcard expression that is matched on
    class names case insensitively.
    The special characters from Unix file name wildcarding are supported
    ('*' to match zero or more characters, '?' to match a single character,
    and '[]' to match character ranges). To avoid shell expansion of wildcard
    characters, the CLASSNAME-GLOB argument should be put in quotes.

    For example, "pywbem_*" returns classes whose name begins with "PyWBEM_",
    "pywbem_", etc. "*system*" returns classes whose names include the case
    insensitive string "system".

    In the output, the classes will be formatted as defined by the
    --output-format general option if it specifies table output. Otherwise
    the classes will be in the form "NAMESPACE:CLASSNAME".

    Examples:

      pywbemcli -n myconn class find "CIM_*System*" -n interop

      pywbemcli -n myconn class find *Foo*
    """
    context.execute_cmd(lambda: cmd_class_find(context, classname_glob,
                                               options))


@class_group.command('tree', cls=PywbemcliCommand, options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=False)
@click.option('-s', '--superclasses', is_flag=True, default=False,
              help='Show the superclass hierarchy. '
                   'Default: Show the subclass hierarchy.')
@add_options(namespace_option)
@add_options(help_option)
@click.pass_obj
def class_tree(context, classname, **options):
    """
    Show the subclass or superclass hierarchy for a class.

    List the subclass or superclass hierarchy of a CIM class (CLASSNAME
    argument) or CIM namespace (--namespace option):

    - If CLASSNAME is omitted, the complete class hierarchy of the specified
      namespace is retrieved.

    - If CLASSNAME is specified but not --superclasses, the class and its
      subclass hierarchy in the specified namespace are retrieved.

    - If CLASSNAME and --superclasses are specified, the class and its
      superclass ancestry up to the top-level class in the specified namespace
      are retrieved.

    If no namespace was specified, the default namespace of the connection is
    used.

    In the output, the classes will formatted as a ASCII graphical tree; the
    --output-format general option is ignored.

    Examples:

      pywbemcli -n myconn class tree -n interop

      pywbemcli -n myconn class tree CIM_Foo -n interop

      pywbemcli -n myconn class tree CIM_Foo -s -n interop
    """
    context.execute_cmd(lambda: cmd_class_tree(context, classname, options))


####################################################################
#
#  Common functions for cmd_class processing
#  This includes functions used by the command action functions
#  in this fmodule and possibly other modules
#
####################################################################


def _build_qualifier_filters(options):
    """
    Build a dictionary defining the qualifier filters to be processes from
    their definitons in the Click options dictionary. There is an entry
    in the dictionary for each qualifier filter where the key is the
    association name and the value is True or False depending in the
    value of the option ('x' or 'no-x' )
    """
    qualifier_filters = {}
    if options['association'] is not None:
        # show_assoc = options['association']
        qualifier_filters['Association'] = options['association']
    if options['indication'] is not None:
        qualifier_filters['Indication'] = options['indication']
    if options['experimental'] is not None:
        qualifier_filters['Experimental'] = options['experimental']
    return qualifier_filters


def _filter_classes_for_qualifiers(qualifier_filters, results, names_only, iq):
    """
    Filter the results list for the qualifiers defined by filter
    qualifier: a dictionary with qualifier name as key and Boolean defining
    whether to display or not display if it exists.

    This method only works for boolean qualifiers
    """

    filtered_results = []
    if results:
        assert isinstance(results[0], CIMClass)
    for cls in results:
        assert isinstance(cls, CIMClass)
        show_this_class = True
        for qname, show_if_true in qualifier_filters.items():
            if qname in cls.qualifiers:
                qvalue = cls.qualifiers[qname].value
                show_this = (qvalue == show_if_true)
            else:
                show_this = not show_if_true
            if not show_this:
                show_this_class = False
                break
        if show_this_class:
            # If returning instances, honor the names_only option
            if not names_only:
                if not iq:
                    cls.qualifiers = []
                    for p in cls.properties.values():
                        p.qualifiers = []
                    for m in cls.methods.values():
                        m.qualifiers = []
                        for p in m.parameters.values():
                            p.qualifiers = []
            filtered_results.append(cls)
    if names_only:
        filtered_results = [cls.classname for cls in filtered_results]
    return filtered_results


def enumerate_classes_filtered(context, classname, options):
    """
    Execute EnumerateClasses or EnumerateClassNames in a single namespace
    defined in options['namespace'] and return results.

    If any of the class qualifier filters are defined in the options parameter,
    enumerate the classes, filter the result for those parameters, and return
    only class names if --names-only set.

    This function may be executed by multiple command action functions with
    varying options in the options. Each option must be tested to validate
    that it exists in the options dictionary

    Parameters:

      context:  Click context

      classname:
        Optional classname for the enumerate.

      options:Click options dictionary
        Options that form basis for this Enumerate and filter processing.

    Returns:
        List of classes or classnames that satisfy the criteria

    Raises:
        pywbem Error exceptions generated by EnumerateClassNames and
        enumerateClasses
    """
    qualifier_filters = _build_qualifier_filters(options)

    names_only = options.get('names_only', False)

    iq = options.get('no_qualifiers', True)

    # Force IncludeQualifier true if results are to be filtered since
    # the filter requires that qualifiers exist.
    request_iq = True if qualifier_filters else iq

    local_only = options.get('local_only', False)
    deep_inheritance = options.get('deep_inheritance', True)
    include_classorigin = options.get('include_classorigin', True)

    if names_only and not qualifier_filters:
        results = context.conn.EnumerateClassNames(
            ClassName=classname,
            namespace=options['namespace'],
            DeepInheritance=deep_inheritance)
    else:
        results = context.conn.EnumerateClasses(
            ClassName=classname,
            namespace=options['namespace'],
            LocalOnly=local_only,
            DeepInheritance=deep_inheritance,
            IncludeQualifiers=request_iq,
            IncludeClassOrigin=include_classorigin)
        if qualifier_filters:
            results = _filter_classes_for_qualifiers(
                qualifier_filters, results,
                names_only, iq)
    return results


def get_format_group(context, options):
    """
    Define the format groups allowed based on the options. This is particular
    to the class commands, largely because we do not have a table format
    for enumerate, get, associators, or references unless options such as
    summary, or names_only are set.
    """

    # Summary always output as TABLE
    if 'summary' in options and options['summary']:

        # This accounts for the fact that the results of a summary can be
        # either table or simply a string output
        if context.output_format and context.output_format in TABLE_FORMATS:
            return ['TABLE']

        # Temporary hack. We need another format group, i.e. txt or str
        # That displays in non-structured manner. Or drop this output
        # completely.
        return ['CIM']

    # Names_only may be output as Table or as CIM Object.
    if 'names_only' in options and options['names_only']:
        return ['CIM', 'TABLE']

    # otherwise only CIM allowed today.
    return ['CIM']


#####################################################################
#
#  Command functions for each of the commands in the class group
#
#####################################################################


def cmd_class_get(context, classname, options):
    """
    Get the class defined by the argument.

    Gets the class defined by CLASSNAME from the WBEM server and displays
    the class. If the class cannot be found, the server returns a CIMError
    exception.
    """
    format_group = get_format_group(context, options)
    output_format = validate_output_format(context.output_format, format_group)

    try:
        result_class = context.conn.GetClass(
            classname,
            namespace=options['namespace'],
            LocalOnly=options['local_only'],
            IncludeQualifiers=options['no_qualifiers'],
            IncludeClassOrigin=options['include_classorigin'],
            PropertyList=resolve_propertylist(options['propertylist']))

        display_cim_objects(context, result_class,
                            output_format=output_format)
    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_invokemethod(context, classname, methodname, options):
    """
    Create an instance and submit to a WBEM server
    """
    try:
        process_invokemethod(context, classname, methodname, options)
    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_enumerate(context, classname, options):
    """
        Enumerate the classes returning a list of classes from the WBEM server.
        That match the qualifier filter options
    """
    format_group = get_format_group(context, options)
    output_format = validate_output_format(context.output_format, format_group)

    try:
        results = enumerate_classes_filtered(context, classname, options)

        display_cim_objects(context, results, output_format,
                            summary=options['summary'], sort=True)

    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_references(context, classname, options):
    """
    Execute the references request operation to get references for
    the classname defined
    """
    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    format_group = get_format_group(context, options)
    output_format = validate_output_format(context.output_format, format_group)

    try:
        if options['names_only']:
            results = context.conn.ReferenceNames(
                classname,
                ResultClass=options['result_class'],
                Role=options['role'])
        else:
            results = context.conn.References(
                classname,
                ResultClass=options['result_class'],
                Role=options['role'],
                IncludeQualifiers=options['no_qualifiers'],
                IncludeClassOrigin=options['include_classorigin'],
                PropertyList=resolve_propertylist(options['propertylist']))

        display_cim_objects(context, results, output_format,
                            summary=options['summary'], sort=True)

    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_associators(context, classname, options):
    """
    Execute the references request operation to get references for
    the classname defined
    """
    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    format_group = get_format_group(context, options)
    output_format = validate_output_format(context.output_format, format_group)

    try:
        if options['names_only']:
            results = context.conn.AssociatorNames(
                classname,
                AssocClass=options['assoc_class'],
                Role=options['role'],
                ResultClass=options['result_class'],
                ResultRole=options['result_role'])
        else:
            results = context.conn.Associators(
                classname,
                AssocClass=options['assoc_class'],
                Role=options['role'],
                ResultClass=options['result_class'],
                ResultRole=options['result_role'],
                IncludeQualifiers=options['no_qualifiers'],
                IncludeClassOrigin=options['include_classorigin'],
                PropertyList=resolve_propertylist(options['propertylist']))

        display_cim_objects(context, results, output_format,
                            summary=options['summary'], sort=True)

    except Error as er:
        raise_pywbem_error_exception(er)


def get_namespaces(context, namespaces):
    """
    Returns either the namespaces provided or if that is None, the set of
    namespaces that are defined in the wbem server as a list

    Raises:
        CIMError if status code not CIM_ERR_NOT_FOUND
    """
    ns_names = []

    # Return the provided namespace(s)
    if namespaces:
        return namespaces

    # Otherwise get all namespaces from server
    try:
        ns_names = context.wbem_server.namespaces
        ns_names.sort()
        return ns_names
    except CIMError as ce:
        # allow processing to continue if no interop namespace
        if ce.status_code == CIM_ERR_NOT_FOUND:
            warning_msg('{}. Using default_namespace {}.'
                        .format(ce, context.conn.default_namespace))
            ns_names = [context.conn.default_namespace]
        return ns_names
    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_find(context, classname_glob, options):
    """
    Execute the command for enumerate classes, filter the results based on the
    option and display the result. The result is a list of classes/namespaces
    """

    output_format = validate_output_format(context.output_format, 'TABLE')

    context.spinner_stop()
    namespaces = get_namespaces(context, options['namespace'])

    try:
        names_dict = {}
        if namespaces:
            for namespace in namespaces:
                # Set cmd options that are required for this command to get
                # information on classes in server.
                # 1. Always use deep_inheritance
                # 2. Set namespace to each namespace in loop
                options['deep_inheritance'] = True
                options['namespace'] = namespace
                options['names_only'] = True

                classnames = enumerate_classes_filtered(context, None, options)
                names_dict[namespace] = filter_namelist(classname_glob,
                                                        classnames)

        # build rows of namespace, classname for each namespace, sort if
        # necessary,  and add to common rows
        rows = []
        for ns_name in names_dict:
            ns_rows = [[ns_name, name] for name in names_dict[ns_name]]
            # sort by classname if sort option defined, else by namespace
            row = 0 if options['sort'] else 1
            ns_rows.sort(key=lambda x: x[row])
            rows.extend(ns_rows)

        context.spinner_stop()
        if context.output_format in TABLE_FORMATS:
            headers = ['Namespace', 'Classname']
            click.echo(
                format_table(rows, headers,
                             title='Find class {}'.format(classname_glob),
                             table_format=output_format))
        else:
            # Display function to display classnames returned with
            # their namespaces in the form <namespace>:<classname>
            context.spinner_stop()
            for row in rows:
                click.echo('  {}:{}'.format(row[0], row[1]))

    except Error as er:
        raise_pywbem_error_exception(er)


def cmd_class_tree(context, classname, options):
    """
    Execute the command to enumerate classes from the top or starting at the
    classname argument. Then format the results to be displayed as a
    left-justified tree using the asciitree library.
    The --superclasses option determines if the superclass tree or the
    subclass tree is displayed.
    """

    # TODO FUTURE: Sort out how we handle output format with tree output.
    try:
        if options['superclasses']:
            if classname is None:
                raise click.ClickException('CLASSNAME argument required for '
                                           '--superclasses option')

            # Get the superclasses into a list
            class_ = context.conn.GetClass(classname,
                                           namespace=options['namespace'])

            # Include target class in display in list
            classes = [class_]
            # Get all superclasses to class_
            while class_.superclass:
                class_ = context.conn.GetClass(class_.superclass,
                                               namespace=options['namespace'])
                classes.append(class_)

            # classname not used when displaying superclasses.
            # display_class_tree sets it to root
            classname = None

        else:
            # Get the subclass hierarchy either complete or starting at the
            # optional CLASSNAME. NOTE: We do not include target_classname
            # in lists of classes sent to display_class_tree. That function
            # attaches it.
            classes = context.conn.EnumerateClasses(
                ClassName=classname,
                namespace=options['namespace'],
                DeepInheritance=True)

            # Get correct case sensitive classname for target class if
            # it exists. Simplifies display_class_tree
            if classname:
                tclass = context.conn.GetClass(classname,
                                               namespace=options['namespace'])
                classname = tclass.classname
    except Error as er:
        raise_pywbem_error_exception(er)

    # Display the list of classes as a tree. The classname is the top
    # of the tree.
    context.spinner_stop()
    display_class_tree(classes, classname)


def cmd_class_delete(context, classname, options):
    """Delete a class from the WBEM server repository"""
    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    try:
        instnames = context.conn.EnumerateInstanceNames(classname)
        subclassnames = context.conn.EnumerateClassNames(ClassName=classname,
                                                         DeepInheritance=True)
    except Error as er:
        raise_pywbem_error_exception(er)

    if subclassnames:
        raise click.ClickException('Delete rejected; subclasses exist')

    if not options['force']:
        if instnames:
            raise click.ClickException('Delete rejected; instances exist')
    else:
        for instname in instnames:
            context.conn.DeleteInstance(instname)

    instnames = context.conn.EnumerateInstanceNames(classname)
    if instnames:
        raise click.ClickException('Delete rejected; instance delete failed')

    try:
        context.conn.DeleteClass(classname)
        if context.verbose:
            context.spinner_stop()
            click.echo('Deleted class {}.'.format(classname))
    except Error as er:
        raise_pywbem_error_exception(er)
