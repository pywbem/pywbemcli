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
cmds for get, enumerate, list of classes.
"""
from __future__ import absolute_import

import click

from pywbem import Error, CIMClassName

from .pywbemcli import cli
from ._common import display_cim_objects, filter_namelist, \
    resolve_propertylist, CMD_OPTS_TXT, TABLE_FORMATS, \
    format_table, process_invokemethod
from ._common_options import propertylist_option, names_only_option, \
    sort_option, includeclassorigin_option, namespace_option, add_options, \
    summary_objects_option

from ._displaytree import display_class_tree


#
#   Common option definitions for class group
#

includeclassqualifiers_option = [              # pylint: disable=invalid-name
    click.option('--no-qualifiers', is_flag=True,
                 required=False, default=True,
                 help='If set, request server to not include qualifiers in '
                      'the returned class(s). The default behavior is to '
                      'request include qualifiers in the returned class(s).')]

deepinheritance_option = [              # pylint: disable=invalid-name
    click.option('-d', '--deepinheritance', is_flag=True, required=False,
                 help='If set, request server to return complete subclass '
                      'hiearchy for this class. The default is False which '
                      'requests only one level of subclasses.')]

# TODO add a case sensitive option for those things that use regex


@cli.group('class', options_metavar=CMD_OPTS_TXT)
def class_group():
    """
    Command group to manage CIM classes.

    In addition to the command-specific options shown in this help text, the
    general options (see 'pywbemcli --help') can also be specified before the
    command. These are NOT retained after the command is executed.
    """
    pass


@class_group.command('get', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@click.option('-l', '--localonly', is_flag=True, required=False,
              help='Show only local properties of the class.')
@add_options(includeclassqualifiers_option)
@add_options(includeclassorigin_option)
@add_options(propertylist_option)
@add_options(namespace_option)
@click.pass_obj
def class_get(context, classname, **options):
    """
    Get and display a single CIM class.

    Get a single CIM class defined by the CLASSNAME argument from the WBEM
    server and display it. Normally it is retrieved from the default namespace
    in the server.

    If the class is not found in the WBEM Server, the server returns an
    exception.

    The --includeclassorigin, --includeclassqualifiers, and --propertylist
    options determine what parts of the class definition are tetrieved.

    Results are formatted as defined by the output format global option.

    """
    context.execute_cmd(lambda: cmd_class_get(context, classname, options))


@class_group.command('delete', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@click.option('-f', '--force', is_flag=True, required=False,
              help='Force the delete request to be issued even if '
              'there are instances in the server or subclasses to this class. '
              'The WBEM Server may still refuse the request.')
@add_options(namespace_option)
@click.pass_obj
def class_delete(context, classname, **options):
    """
    Delete a single class.

    Deletes the class defined by CLASSNAME from the WBEM Server.

    If the class has instances, the command is refused unless the
    --force option is used. If --force is used, instances are also
    deleted.

    WARNING: Removing classes from a WBEM Server can cause damage to the
    server. Use this with caution.  It can impact instance providers and
    other components in the server.

    Some servers may refuse the operation.
    """
    context.execute_cmd(lambda: cmd_class_delete(context, classname, options))


@class_group.command('invokemethod', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True,)
@click.argument('methodname', type=str, metavar='METHODNAME', required=True)
@click.option('-p', '--parameter', type=str, metavar='parameter',
              required=False, multiple=True,
              help='Optional multiple method parameters of form name=value')
@add_options(namespace_option)
@click.pass_obj
def class_invokemethod(context, classname, methodname, **options):
    """
    Invoke the class method named methodname.

    This invokes the method named METHODNAME on the class named CLASSNAME.

    This is the class level invokemethod and uses only the class name on the
    invoke.The subcommand `instance invokemethod` invokes methods based on
    class name.

    Examples:

      pywbemcli invokemethod CIM_Foo methodx -p param1=9 -p param2=Fred
    """
    context.execute_cmd(lambda: cmd_class_invokemethod(context,
                                                       classname,
                                                       methodname,
                                                       options))


@class_group.command('enumerate', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=False)
@click.option('-d', '--deepinheritance', is_flag=True, required=False,
              help='Return complete subclass hierarchy for this class if '
                   'set. Otherwise retrieve only the next hierarchy level.')
@click.option('-l', '--localonly', is_flag=True, required=False,
              help='Show only local properties of the class.')
@add_options(includeclassqualifiers_option)
@add_options(includeclassorigin_option)
@add_options(names_only_option)
@add_options(sort_option)
@add_options(namespace_option)
@add_options(summary_objects_option)
@click.pass_obj
def class_enumerate(context, classname, **options):
    """
    Enumerate classes from the WBEM Server.

    Enumerates the classes (or classnames) from the WBEMServer starting
    either at the top of the class hierarchy or from  the position in the
    class hierarchy defined by `CLASSNAME` argument if provided.

    The output format is defined by the output-format global option.

    The includeclassqualifiers, includeclassorigin options define optional
    information to be included in the output.

    The deepinheritance option defines whether the complete hiearchy is
    retrieved or just the next level in the hiearchy.

    Results are formatted as defined by the output format global option.
    """
    context.execute_cmd(lambda: cmd_class_enumerate(context, classname,
                                                    options))


@class_group.command('references', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True)
@click.option('-R', '--resultclass', type=str, required=False,
              metavar='<class name>',
              help='Filter by the result classname provided. Each returned '
                   'class (or classname) should be this class or its '
                   'subclasses. Optional.')
@click.option('-r', '--role', type=str, required=False,
              metavar='<role name>',
              help='Filter by the role name provided. Each returned class '
                   '(or classname) should refer to the target instance through '
                   'a property with a name that matches the value of this '
                   'parameter. Optional.')
@add_options(includeclassqualifiers_option)
@add_options(includeclassorigin_option)
@add_options(propertylist_option)
@add_options(names_only_option)
@add_options(sort_option)
@add_options(namespace_option)
@add_options(summary_objects_option)
@click.pass_obj
def class_references(context, classname, **options):
    """
    Get the reference classes for CLASSNAME.

    Get the reference classes (or class names) for the CLASSNAME argument
    filtered by the role and result class options and modified by the
    other options.

    Results are displayed as defined by the output format global option.
    """
    context.execute_cmd(lambda: cmd_class_references(context, classname,
                                                     options))


@class_group.command('associators', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=True)
@click.option('-a', '--assocclass', type=str, required=False,
              metavar='<class name>',
              help='Filter by the association class name provided. Each '
                   'returned class (or class name) should be associated to the '
                   'source class through this class or its subclasses. '
                   'Optional.')
@click.option('-c', '--resultclass', type=str, required=False,
              metavar='<class name>',
              help='Filter by the association result class name provided. Each '
                   'returned class (or class name) should be this class or one '
                   'of its subclasses. Optional')
@click.option('-r', '--role', type=str, required=False,
              metavar='<role name>',
              help='Filter by the role name provided. Each returned class '
              '(or class name)should be associated with the source class '
              '(CLASSNAME) through an association with this role (property '
              'name in the association that matches this parameter). Optional.')
@click.option('-R', '--resultrole', type=str, required=False,
              metavar='<role name>',
              help='Filter by the result role name provided. Each returned '
              'class (or class name)should be associated with the source class '
              '(CLASSNAME) through an association with returned object having '
              'this role (property name in the association that matches this '
              'parameter). Optional.')
@add_options(includeclassqualifiers_option)
@add_options(includeclassorigin_option)
@add_options(propertylist_option)
@add_options(names_only_option)
@add_options(sort_option)
@add_options(namespace_option)
@add_options(summary_objects_option)
@click.pass_obj
def class_associators(context, classname, **options):
    """
    Get the associated classes for CLASSNAME.

    Get the classes(or class names) that are associated with the CLASSNAME
    argument filtered by the --assocclass, --resultclass, --role and
    --resultrole options and modified by the other options.

    Results are formatted as defined by the output format global option.
    """
    context.execute_cmd(lambda: cmd_class_associators(context, classname,
                                                      options))


@class_group.command('find', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME-REGEX', required=True)
@add_options(sort_option)
@add_options(namespace_option)
@click.pass_obj
def class_find(context, classname, **options):
    """
    Find all classes that match CLASSNAME-REGEX.

    Find all classes in the namespace(s) of the target WBEMServer that
    match the CLASSNAME-REGEX regular expression argument. The CLASSNAME-REGEX
    argument is required.

    The CLASSNAME-REGEX argument may be either a complete classname or a regular
    expression that can be matched to one or more classnames. To limit the
    filter to a single classname, terminate the classname with $.

    The regular expression is anchored to the beginning of the classname and
    is case insensitive. Thus, `pywbem_` returns all classes that begin with
    `PyWBEM_`, `pywbem_`, etc.

    The namespace option limits the search to the defined namespace. Otherwise
    all namespaces in the target server are searched.

    Output is in table format if table output specified. Otherwise it is in the
    form <namespace>:<classname>
    """
    context.execute_cmd(lambda: cmd_class_find(context, classname, options))


@class_group.command('tree', options_metavar=CMD_OPTS_TXT)
@click.argument('classname', type=str, metavar='CLASSNAME', required=False)
@click.option('-s', '--superclasses', is_flag=True, required=False,
              default=False,
              help='Display the superclasses to CLASSNAME as a tree.  When '
                   'this option is set, the CLASSNAME argument is required')
@add_options(namespace_option)
@click.pass_obj
def class_tree(context, classname, **options):
    """
    Display CIM class inheritance hierarchy tree.

    Displays a tree of the class hiearchy to show superclasses and subclasses.

    CLASSNAMe is an optional argument that defines the starting point for the
    hiearchy display

    If the --superclasses option not specified the hiearchy starting either
    at the top most classes of the class hiearchy or at the class defined by
    CLASSNAME is displayed.

    if the --superclasses options is specified and a CLASSNAME is defined
    the class hiearchy of superclasses leading to CLASSNAME is displayed.

    This is a separate subcommand because it is tied specifically to displaying
    in a tree format.so that the --output-format global option is ignored.
    """
    context.execute_cmd(lambda: cmd_class_tree(context, classname, options))

#####################################################################
#
#  Command functions for each of the subcommands in the class group
#
#####################################################################


def cmd_class_get(context, classname, options):
    """
    Get the class defined by the argument.

    Gets the class defined by CLASSNAME from thw wbem server and displays
    the class. If the class cannot be found, the server returns a CIMError
    exception.

    """
    try:
        result_class = context.conn.GetClass(
            classname,
            namespace=options['namespace'],
            LocalOnly=options['localonly'],
            IncludeQualifiers=options['no_qualifiers'],
            IncludeClassOrigin=options['includeclassorigin'],
            PropertyList=resolve_propertylist(options['propertylist']))

        display_cim_objects(context, result_class,
                            output_format=context.output_format)
    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))


def cmd_class_invokemethod(context, classname, methodname, options):
    """
    Create an instance and submit to wbemserver
    """
    try:
        process_invokemethod(context, classname, methodname, options)
    except Exception as ex:
        raise click.ClickException("%s: %s" % (ex.__class__.__name__, ex))


def cmd_class_enumerate(context, classname, options):
    """
        Enumerate the classes returning a list of classes from the WBEM server.
    """
    # results may be either classes or classnames
    try:
        if options['names_only']:
            results = context.conn.EnumerateClassNames(
                ClassName=classname,
                namespace=options['namespace'],
                DeepInheritance=options['deepinheritance'])
            if options['sort']:
                results.sort()
        else:
            results = context.conn.EnumerateClasses(
                ClassName=classname,
                namespace=options['namespace'],
                LocalOnly=options['localonly'],
                DeepInheritance=options['deepinheritance'],
                IncludeQualifiers=options['no_qualifiers'],
                IncludeClassOrigin=options['includeclassorigin'])
            if options['sort']:
                results.sort(key=lambda x: x.classname)

        display_cim_objects(context, results, context.output_format,
                            summary=options['summary'])

    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))


def cmd_class_references(context, classname, options):
    """Execute the references request operation to get references for
       the classname defined
    """
    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    try:
        if options['names_only']:
            results = context.conn.ReferenceNames(
                classname,
                ResultClass=options['resultclass'],
                Role=options['role'])
            if options['sort']:
                results.sort()
        else:
            results = context.conn.References(
                classname,
                ResultClass=options['resultclass'],
                Role=options['role'],
                IncludeQualifiers=options['includequalifiers'],
                IncludeClassOrigin=options['includeclassorigin'],
                PropertyList=resolve_propertylist(options['propertylist']))
            if options['sort']:
                results.sort(key=lambda x: x[1].classname)

        display_cim_objects(context, results, context.output_format,
                            summary=options['summary'])

    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))


def cmd_class_associators(context, classname, options):
    """Execute the references request operation to get references for
       the classname defined
    """
    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    try:
        if options['names_only']:
            results = context.conn.AssociatorNames(
                classname,
                AssocClass=options['assocclass'],
                Role=options['role'],
                ResultClass=options['resultclass'],
                ResultRole=options['resultrole'])
            if options['sort']:
                results.sort()
        else:
            results = context.conn.Associators(
                classname,
                AssocClass=options['assocclass'],
                Role=options['role'],
                ResultClass=options['resultclass'],
                ResultRole=options['resultrole'],
                IncludeQualifiers=options['includequalifiers'],
                IncludeClassOrigin=options['includeclassorigin'],
                PropertyList=resolve_propertylist(options['propertylist']))
            if options['sort']:
                results.sort(key=lambda x: x[1].classname)

        display_cim_objects(context, results, context.output_format,
                            summary=options['summary'])

    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))


def cmd_class_find(context, classname, options):
    """
    Execute the command for get class and display the result. The result is
    a list of classes/namespaces
    """
    if options['namespace']:
        ns_names = options['namespace']
    else:
        ns_names = context.wbem_server.namespaces
        if options['sort']:
            ns_names.sort()

    try:
        names_dict = {}
        for ns in ns_names:
            classnames = context.conn.EnumerateClassNames(
                namespace=ns, DeepInheritance=True)
            filtered_classnames = filter_namelist(classname, classnames)
            if options['sort']:
                filtered_classnames.sort()
            names_dict[ns] = filtered_classnames

        # TODO we sort twice (above and below)

        rows = []
        for ns_name in names_dict:
            ns_rows = [[ns_name, name] for name in names_dict[ns_name]]
            # sort the result by classname
            ns_rows.sort(key=lambda x: x[1])
            rows.extend(ns_rows)

        if context.output_format in TABLE_FORMATS:
            headers = ['Namespace', 'Classname']
            click.echo(format_table(rows, headers,
                                    table_format=context.output_format,
                                    title='Find class %s' % classname))
        else:
            # Display function to display classnames returned with
            # their namespaces in the form <namespace>:<classname>
            for row in rows:
                print('  %s:%s' % (row[0], row[1]))

    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))


def cmd_class_tree(context, classname, options):
    """
    Execute the command to enumerate classes from the top or starting at the
    classname argument. Then format the results to be displayed as a
    left-justified tree using the asciitree library.
    The superclasses option determines if the superclass tree or the
    subclass tree is displayed.
    """
    try:
        if options['superclasses']:
            if classname is None:
                raise click.ClickException('Classname argument required for '
                                           'superclasses option')

            # get the superclasses into a list
            class_ = context.conn.GetClass(classname,
                                           namespace=options['namespace'])
            classes = []
            classes.append(class_)
            while class_.superclass:
                class_ = context.conn.GetClass(class_.superclass,
                                               namespace=options['namespace'])
                classes.append(class_)
            classname = None

        else:
            # get the subclass hierarchy either complete or starting at the
            # optional CLASSNAME
            classes = context.conn.EnumerateClasses(
                ClassName=classname,
                namespace=options['namespace'],
                DeepInheritance=True)
    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))

    # display the list of classes as a tree. The classname is the top
    # of the tree.
    context.spinner.stop()
    display_class_tree(classes, classname)


def cmd_class_delete(context, classname, options):
    """Delete a class from the wbemserver repository"""

    if options['namespace']:
        classname = CIMClassName(classname, namespace=options['namespace'])

    if not options['force']:
        insts = context.conn.PyWbemCLIEnumerateInstancePaths(classname)
        if insts:
            raise click.ClickException('Ignored; instances exist')
        # TODO test for subclasses

    try:
        context.conn.DeleteClass(classname)
        click.echo('%s delete successful' % classname)
    except Error as er:
        raise click.ClickException("%s: %s" % (er.__class__.__name__, er))
