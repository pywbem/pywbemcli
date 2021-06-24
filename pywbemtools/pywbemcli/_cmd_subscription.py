# (C) Copyright 2021 IBM Corp.
# (C) Copyright 2021 Inova Development Inc.
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
Click Command definition for the subscrription command group which includes
cmds for managing subscriptions to indications on servers that uses the
pywbem WBEMSubscriptionManager class.
"""
from __future__ import absolute_import

import re

from urllib.parse import urlparse

import click

from pywbem import Error, WBEMSubscriptionManager, Uint32, CIMClassName, \
    CIM_ERR_ALREADY_EXISTS

from .pywbemcli import cli

from .._options import add_options, help_option

from ._display_cimobjects import display_cim_objects

from .._click_extensions import CMD_OPTS_TXT

from ._common import pick_one_from_list, sort_cimobjects

from .._output_formatting import validate_output_format, \
    output_format_is_table, output_format_is_cimobject, format_table

DEFAULT_QUERY_LANGUAGE = 'WQL'

DEFAULT_SUB_MGR_ID = "pywbemcliSubMgr"

OWNED = True
ALL = False

sub_mgr_id_option = [              # pylint: disable=invalid-name
    click.option('-i', '--submgr-id', type=str, required=False,
                 default=DEFAULT_SUB_MGR_ID,
                 help=u'Optional subscription manager id that can be used to '
                      u'separate subscriptions created by pywbem. '
                      'Default: {id}'.
                      format(id=DEFAULT_SUB_MGR_ID)),
]

owned_type_option = [              # pylint: disable=invalid-name
    click.option('--owned', is_flag=True, default=False,
                 help=u'Limit the operation to owned subscriptions, '
                      u'listener destinations or filters. Default: {}'
                      .format(False)),
]


# TODO test for positive integer here.
listener_port_option = [              # pylint: disable=invalid-name
    click.option('-p', '--listener-port', type=int, metavar='listener_port',
                 required=True,
                 help='Listener destination port to receive indications')
]

filter_id_option = [              # pylint: disable=invalid-name
    click.option('--filter-id', type=str, metavar='TEXT',
                 required=False,
                 help='Text that is used to define the name parameter.')
]


filter_name_option = [              # pylint: disable=invalid-name
    click.option('--name', type=str, metavar='TEXT',
                 required=False,
                 help='Value for the name parameter.')
]

paths_option = [              # pylint: disable=invalid-name
    click.option('-p', '--paths', is_flag=True, required=False,
                 help='Show CIMInstanceName elements of the instances.')
]

detail_option = [             # pylint: disable=invalid-name
    click.option('-d', '--detail', is_flag=True, required=False,
                 help="Show all properties of the instances. Otherwise only "
                 "non-null or predefined property values are displayed. It "
                 "applies to both MOF and TABLE output formats")
]

summary_option = [             # pylint: disable=invalid-name
    click.option('-s', '--summary', is_flag=True, required=False,
                 help='If True, show only summary count of instances ')
]

##################################################################
#
# Subcommand Click definitions
#
###################################################################


@cli.group('subscription', options_metavar=CMD_OPTS_TXT)
def subscription_group():
    """
    Command group to manage WBEM indication subscriptions.

    This group uses the pywbem subscription manager to view and manage
    CIM Indication subscriptions for a WBEM Server.

    In addition to the command-specific options shown in this help text, the
    general options (see 'pywbemcli --help') can also be specified before the
    command. These are NOT retained after the command is executed.
    """
    pass


@subscription_group.command('list', options_metavar=CMD_OPTS_TXT)
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(detail_option)
@add_options(paths_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def subscription_list(context, **options):
    """
    List indication subscriptions overview.

    This command provides an overview of the subscriptions, filters, and
    destinations
    """
    context.execute_cmd(lambda: cmd_subscription_list(context, options))


@subscription_group.command('list-subscriptions', options_metavar=CMD_OPTS_TXT)
# TODO: we don't have way to filter what we see for subscriptions.'
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(detail_option)
@add_options(paths_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def subscription_list_subscriptions(context, **options):
    """
    List indication subscription on the WBEM server.

    This command displays the subscriptions on the WBEM server filtering
    the subscriptions by the owned option.

    It displays the instances or paths. TODO:

    """
    context.execute_cmd(lambda: cmd_subscription_list_subscriptions(
        context, options))


@subscription_group.command('list-filters', options_metavar=CMD_OPTS_TXT)
@add_options(filter_name_option)
@add_options(filter_id_option)
@add_options(owned_type_option)
# @add_options(sub_mgr_id_option)
@add_options(detail_option)
@add_options(paths_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def subscription_list_filters(context, **options):
    """
    List indication filters on the WBEM server.

    List existing CIM indication subscriptions on the current
    connection. The indications filters to be displayed can be filtered by the
    filter naming options and the owned option.

    The data display is determined by the detail, paths, and summary options
    and can be displayed as either a table or CIM objects (ex. mof) format.

    """
    context.execute_cmd(lambda: cmd_subscription_list_filters(context, options))


@subscription_group.command('list-destinations', options_metavar=CMD_OPTS_TXT)
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(detail_option)
@add_options(paths_option)
@add_options(summary_option)
@add_options(help_option)
@click.pass_obj
def subscription_list_destinations(context, **options):
    """
    list indication listener destinations on the WBEM server.

    List the existing CIM indication destinations on the current
    connection. The list returned can be modified with the options that
    define owned.

    The data display is determined by the detail, paths, and summary options
    and can be displayed as either a table or CIM objects (ex. mof) format.

    """
    context.execute_cmd(lambda: cmd_subscription_list_destinations(context,
                                                                   options))


@subscription_group.command('add-subscription', options_metavar=CMD_OPTS_TXT)
@click.option('--select', is_flag=True, default=False,
              help="Select filter and destination to include in this "
                   "subscription.")
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_add_subscription(context, **options):
    """
    Add a new indication subscription.

    Add a subscription to a WBEM server defined by the server_id for a
    particular set of indications defined by an indication filter and for a
    particular WBEM listener defined by the instance path of the listener
    destinations, by creating indication subscription instances (of CIM class
    "CIM_IndicationSubscription") in the Interop namespace of the server.

    The specified indication filter may be owned, permanent or static.

    The specified listener destinations may be owned, permanent or static.

    When creating permanent subscriptions, the indication filter and the
    listener destinations must not be owned.

    Owned subscriptions are added or updated conditionally: If the
    subscription instance to be added is already registered with
    this subscription manager and has the same path , it is not
    created.

    Permanent subscriptions are created unconditionally, and it is up to
    the user to ensure that such an instance does not exist yet.

    Upon successful return of this method, the added subscription is
    active, so that the specified WBEM listeners may immediately receive
    indications.

    """
    context.execute_cmd(lambda: cmd_subscription_add_subscription(context,
                                                                  options))


@subscription_group.command('add-filter', options_metavar=CMD_OPTS_TXT)
@click.option('-q', '--query', type=str, metavar='filter',
              help='Filter query definition. This is a SELECT '
                   'statement in the query language defined in the '
                   'filter-query-language parameter')
@click.option('--query-language', type=str, metavar='TEXT',
              default=DEFAULT_QUERY_LANGUAGE,
              help='Filter query language for this subscription The query '
                   'languages normally implemented are "DMTF:CQL" and "WQL" . '
                   ' Default: {}' .format(DEFAULT_QUERY_LANGUAGE))
@click.option('--source-namespace', type=str, metavar='TEXT',
              default=None, required=False,
              help='The namespace for which the query is defined. If not '
                   ' defined, the default namespace of the server is used')
@add_options(filter_name_option)
@add_options(filter_id_option)
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_add_filter(context, **options):
    """
    Add a new indication filter.

    This command adds a :term:`dynamic indication filter` to a WBEM server, by
    creating an indication filter instance (of CIM class
    "CIM_IndicationFilter") in the Interop namespace of the server.

    The new indication filter is defined by the input parameters.  If the
    options are --owned and --filter_id, the filter is only added if there is
    no filter with the same filter_id in the WBEM server. Otherwise, the
    existing filter with the defined_filter_id is modified

    if --owned is not specified, either the --filter-id or --name
    parameter may be used to define the filter ``Name`` property.

    The --name option should be used in cases where the user needs to have
    control over the filter name (e.g. because a DMTF management profile
    requires a particular name), but it cannot be used for owned filters.

    Owned indication filters are added or updated conditionally: If the
    indication filter instance to be added is already registered with
    this subscription manager and has the same property values, it is not
    created or modified. If it has the same path but different property
    values, it is modified to get the desired property values. If an
    instance with this path does not exist yet (the normal case), it is
    created.

    Permanent indication filters are created unconditionally, and it is
    up to the user to ensure that such an instance does not exist yet.

    """
    context.execute_cmd(lambda: cmd_subscription_add_filter(context, options))


@subscription_group.command('add-destinations', options_metavar=CMD_OPTS_TXT)
@click.option('-l', '--listener-url', type=str, metavar='URL',
              multiple=True,
              help='Add a listener destination url for indications. this '
                   'includes the schema (http or https, the host name and the '
                   'listener port. Multiple destinations may be added by '
                   'repeating this option')
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_add_destinations(context, **options):
    """
    Add new listener destinations.

    A listener destination defines the location of a WBEM indication
    listener (the URL including port) that defines the indication listener
    for indications exported from a WBEM server.

    This command automatically creates a listener destination instance
    (CIM class "CIM_ListenerDestinationCIMXML") for each specified
    listener URL in the Interop namespace of the specified WBEM server.

    The listener destination is created on the target
    WBEM server.

    """
    context.execute_cmd(lambda: cmd_subscription_add_destinations(
        context, options))


@subscription_group.command('remove-subscription', options_metavar=CMD_OPTS_TXT)
@click.option('--select', is_flag=True, default=False,
              help="Select filter to delete from select list of filters.")
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_remove_subscription(context, **options):
    """
    Delete an indication subscription from the WBEM server.

    This command deletes the indication subscription instances from the
    WBEM server.

    TODO: Today the only options is to select the list of subscriptions to
    be deleted.

    The indication subscriptions must be owned or permanent (i.e. not
    static).

    This operation does not remove associated filter or destination
    instances.
    """
    context.execute_cmd(lambda: cmd_subscription_remove_subscription(context,
                                                                     options))


@subscription_group.command('remove-filter', options_metavar=CMD_OPTS_TXT)
@click.option('--select', is_flag=True, default=False,
              help="Select filter to delete from select list of filters.")
@add_options(filter_name_option)
@add_options(filter_id_option)
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_remove_filter(context, **options):
    """
    Delete an indication filter from the WBEM server.

    If the indication filter  is found it is removed from the WBEM server.

    The indication filters to be removed is identified by either the filter_id
    or the name parameter and whether it is owned or not.

    The --select option allows the user to get a list of the paths of
    filters and selecting one to be removed
    """
    context.execute_cmd(lambda: cmd_subscription_remove_filter(context,
                                                               options))


@subscription_group.command('remove-destination', options_metavar=CMD_OPTS_TXT)
@click.option('-l', '--listener-url', type=str, metavar='URL',
              multiple=True,
              help='URL of the destination to remove. This '
                   'includes the schema (http or https, the host name and the '
                   'listener port. ')
# TODO: What about the name component of the instance at least for not owned.
@click.option('--select', is_flag=True, default=False,
              help="Select filter to delete from select list of filters.")
# @add_options(sub_mgr_id_option)
@add_options(owned_type_option)
@add_options(help_option)
@click.pass_obj
def subscription_remove_destination(context, **options):
    """
    Delete a destination from the WBEM server.

    Removes a single listener destination instance from the WBEM server
    where the instance to be removed can be identified by selecting the
    object from a list of either owned or all destinations or by the
    URL defined in the instance.

    The owned option defines whether the list of owned destinations or all
    destinations is searched for the listener-url

    Some listener_destination instances on a server may be static in which
    case an attempt to remove them will fail.

    # TODO: What about owned and multiples.

    """
    context.execute_cmd(lambda: cmd_subscription_remove_destination(context,
                                                                    options))


@subscription_group.command('send-test-indication',
                            options_metavar=CMD_OPTS_TXT)
@click.option('-l', '--listener-url', type=str, metavar='URL',
              default='http://localhost:25989',
              help='Listener destination url for indications. Default:{}'.
              format("http://localhost:25989"))
@click.option('--count', type=int, metavar="COUNT",
              default=10,
              help="Number of test indications to be requested. Default:{}.".
              format(10))
# @add_options(sub_mgr_id_option)
@add_options(help_option)
@click.pass_obj
def subscription_send_test_indication(context, **options):
    """
    Generate test indications.  This command executes a WBEM server dependent
    set of requests to generate test indications.

    Today, it only works for the OpenPegasus WBEM server and only if specific
    classes are implemented in a provider on the server.  It creates an owned
    subscription and sends a method that tells the server to generate a
    number of test indications.

    If the owned option is set, the command will issue a message and wait for
    the user and then complete which will close the subscription.  If not
    owned, the user must later delete the subscription.

    """
    context.execute_cmd(lambda: cmd_subscription_send_test_indication(
        context, options))


@subscription_group.command('remove-server', options_metavar=CMD_OPTS_TXT)
@add_options(help_option)
@click.pass_obj
def subscription_remove_servers(context, **options):
    """
    Remove the server identified by the server_id. This command also
    unregisters listeners from these servers and removes all owned
    indication subscriptions, owned indication filters, and owned listener
    destinations

    """
    context.execute_cmd(lambda: cmd_subscription_remove_servers(context,
                                                                options))

#####################################################################
#
# Class to communicate with WBEMSubscriptionManager
#
#####################################################################


class CmdSubscriptionManager(object):
    """
    Encapsulate the initial parsing and common variables of subscriptions in
    a single class and provide a set of methods that mirror the
    SubscriptionManager class but for the defined subscription manager id and
    server id.

    All communication with the WBEMSubscriptionManager go through this class
    and the exceptions from WBEMSubscriptionManager are captured in these
    methods to simplify the command action functions.

    Some of the WBEMSubscriptionManager methods have been compressed from
    multiple (owned/all) into a single method with an owned parameter.
    """
    def __init__(self, context, options):
        """
        Initialize the CmdSubscriptionManager instance and the
        WBEMSubscriptionManager instance with the subscriptionmananager_id
        defined.  This retrieves any owned objects from the WBEMServer defined
        by the server_id.
        Parameters:

          context TODO:

          options TODO:
        """
        if not context.pywbem_server_exists():
            raise click.ClickException("No WBEM server defined.")
        if 'submgr_id' in options:
            self._submgr_id = options['submgr_id']
        else:
            self._submgr_id = DEFAULT_SUB_MGR_ID
        self._submgr = WBEMSubscriptionManager(
            subscription_manager_id=self._submgr_id)

        # Register the server in the subscription manager:
        # This also gets all owned subscriptions, filters, and destinations
        # from the server. It does NOT get non-owned objects.
        self._server_id = self._submgr.add_server(
            context.pywbem_server.wbem_server)

    @property
    def server_id(self):
        """
        Return the server_id.
        """
        return self._server_id

    @property
    def submgr(self):
        """
        Return the submanager object
        """
        return self._submgr

    @property
    def submgr_id(self):
        """
        Return the subscription manager id string
        """
        return self._submgr_id

    def get_subscriptions(self, owned):
        """
        Get all of the subscriptions from the server
        """
        try:
            if owned:
                return self.submgr.get_owned_subscriptions(self.server_id)
            else:
                return self.submgr.get_all_subscriptions(self.server_id)
        except Error as er:
            raise click.ClickException(
                self.err_msg("Get indication subscriptions failed", er))

    def get_filters(self, owned):
        """
        Get either the owned indication filters or all indication filters
        from WBEMSubscriptionManager.

        Parameters:

          owned (:class:`py:bool`):
            If True,return only owned filters. Otherwise return all filters
            the match to the filter_id or name

        Returns:
            List of CIM_IndicationFilter objects

        Raises:
            click.ClickException if the request encounters an error.

        """

        try:
            if owned:
                return self.submgr.get_owned_filters(self.server_id)
            else:
                return self.submgr.get_all_filters(self.server_id)
        except Error as er:
            raise click.ClickException(self.err_msg(
                                       "Get indication filters failed", er))

    def get_destinations(self, owned):
        """
        Get either the owned destination instances or all destination instances
        from WBEMSubscriptionManager.

        Parameters:

          owned (:class:`py:bool`):
            If True,return only owned destination instances. Otherwise return
            all destination instances the match to the filter_id or name

        Returns:
            List of CIM_ListenerDestination objects

        Raises:
            click.ClickException if the request encounters an error.
        """
        try:
            if owned:
                return self.submgr.get_owned_destinations(self.server_id)
            else:
                return self.submgr.get_all_destinations(self.server_id)

        except Error as er:
            raise click.ClickException(self.err_msg(
                                       "Get owned indication destinations "
                                       "failed", er))

    def find_owned_listener(self, listener_url):
        """
        Find an owned listener with the listener_url defined in the input
        parameter is one exists. There should not be more than one, ever.

        Parameters:

          listener_url TODO:

        Returns:
            Instance of matching destination object if found or None
        """
        for dest_inst in self.get_destinations(True):
            if dest_inst['Destination'] == listener_url:
                return dest_inst
        return None

    def add_listener_destinations(self, listener_urls, owned):
        """
        Add listener destinations. We keep the same name as the
        SubscriptionManger. Adds one or more listener destinations to
        the WBEM server target.

        See pywbem WBEMSubscriptionManager for details of the parameters

        Returns:
          list of destinations created (compatible with subscription mgr)
        """

        # If the listener is owned, attempt to find already existing
        # listener. Do not build multiple owned listeners with the
        # same listener_url
        urls_to_add = []
        if owned:
            for url in listener_urls:
                dest = self.find_owned_listener(url)
            if dest is not None:
                if self.context.verbose:
                    click.echo("Owned URL {} already exists.". format(url))
                else:
                    urls_to_add.append(dest)
        else:
            urls_to_add = listener_urls

        try:
            dests = self.submgr.add_listener_destinations(self.server_id,
                                                          listener_urls, owned)
            return dests
        except Error as er:
            if er.status_code == CIM_ERR_ALREADY_EXISTS:
                raise click.ClickException(
                    "Add Destination Failed. Destination listener_url={} "
                    "already exists. Exception: {}".format(listener_urls, er))
            raise click.ClickException(self.err_msg(
                                       "Add listener destinations failed", er))

    def add_filter(self, source_namespace, query,
                   query_language=DEFAULT_QUERY_LANGUAGE, owned=True,
                   filter_id=None, name=None):
        """
        Add an indication filter calls WBEMSubscriptionManager.add_filter and
        captures exceptions.  See WBEMSubscriptionManager for details of
        parameters.
        """
        try:
            return self.submgr.add_filter(self.server_id,
                                          source_namespace,
                                          query,
                                          query_language=query_language,
                                          owned=owned,
                                          filter_id=filter_id,
                                          name=name)
        except ValueError as ve:
            raise click.ClickException(
                self.err_msg("Add filter failed. Pywbem parameter error", ve))
        except Error as er:
            if er.status_code == CIM_ERR_ALREADY_EXISTS:
                name_value = filter_id or name
                raise click.ClickException("Add Indication filter Failed. "
                                           "Filter name={} already exists".
                                           format(name_value))

            raise click.ClickException(self.err_msg(
                                       "Add listener destinations failed", er))

    def add_subscriptions(self, filter_path, destination_paths=None,
                          owned=True):
        """
        Add the subscription defined by filter_path and dest_path. Note that
        if the path of the subscription already exists it is not added.
        The ownership is defined by the ownership of the filter and
        destination and they must match
        """
        try:
            return self.submgr.add_subscriptions(
                self.server_id, filter_path,
                destination_paths=destination_paths,
                owned=owned)
        except Error as er:
            raise click.ClickException(self.err_msg("Add subscription failed",
                                                    er))

    def remove_filter(self, filter_path):
        try:
            return self.submgr.remove_filter(self.server_id, filter_path)
        except Error as er:
            raise click.ClickException(
                self.err_msg("Remove filter path {} failed".format(filter_path),
                             er))

    def remove_destinations(self, destination_path):
        """
        Remove the destination instance defined by the destination instance
        parameter.
        """
        try:
            return self.submgr.remove_destinations(self.server_id,
                                                   destination_path)
        except Error as er:
            raise click.ClickException(self.err_msg("Remove Destination failed",
                                                    er))

    def remove_subscriptions(self, subscription_path):
        """
        Remove a subscription
        """
        try:
            return self.submgr.remove_subscriptions(self.server_id,
                                                    subscription_path)
        except Error as er:
            raise click.ClickException(self.err_msg(
                "Remove subscription failed", er))

    def remove_server(self):
        """
        Remove the server defined by the server_id from the subscription
        manager and also unregister add destinations and remove owned
        destinations, filters, and subscriptions from the server.
        """
        try:
            self.submgr.remove_server(self.server_id)
        except Error as er:
            raise click.ClickException(self.err_msg("Remove Server failed",
                                                    er))

    def find_owned_filters(self, filter_id):
        """
        Find filters in the list of owned filters that matches the input
        criteria. Match includes:
         - the same filter_id,
         - the same value for

         TODO: Should we also match the other properties in the filter or
         can we match them based on filterid.
         TODO: Should we have an early test that simply rejects an add
         filter with existing filter_id
        """
        owned = []
        # define regex that matches on filter_id.
        # subscription manager ID, etc. should already be matched.
        filter_name_pattern = re.compile(
            r'^pywbemfilter:owned:[^:]+:{0}:{1}:[^:]*$'.format(self.submgr_id,
                                                               filter_id))
        # search owned filters for filter_id match
        for inst in self.submgr.get_filters(self.server_id, OWNED):
            if re.match(filter_name_pattern, inst.path.keybindings['Name']):
                owned.append(inst)

        return owned

    def get_filter_id(self, path):
        """
        Get the filter_id from a filter path element.

        Parameters:
          path (:class: `CIMInstanceName`)
            The CIMInstanceName to be inspected for a Name key that
            matches the pattern defined in pywbem for filter instances
            that would be defined by a filter_id.

        Returns:
           String containing the filter_id if the path Name key contains
           a filter_id filter or None if the filter_id cannot be found.

        Raises:
            click.ClickException if filter_id cannot be retrieved.
        """
        # Decide whether split or regex is better solution.
        # Filter for owned and filter_id
        # filter_name_pattern = re.compile(
        #    r'^pywbemfilter:([^:]+):([^:]+):{0}:([^:]+):'.format(
        #    self.submgr_id))
        # m = re.match(filter_name_pattern, path.keybindings['Name'])
        parts = path.keybindings['Name'].split(':')

        if len(parts) < 6 or parts[0] != "pywbemfilter":
            raise click.ClickException("Error parsing 'Name' property {} for "
                                       "filter_id. "
                                       "Result {}".format(
                                           path.keybindings['Name'],
                                           "".join(parts)))
        return parts[4]

    def find_matching_filters(self, filter_id, name, owned):
        """
        Return list of filters that match the owned parameter and where the
        filter matches either the filter_id or owned parameter

        Parameters:
          filter_id (:term:`string` or None):
            If this is not None a string match using name pattern

          name (:term:`string` or None):
            if this is not None, match the Name property

          owned  (:class:`py:bool`):
            If True, process only owned filters. Otherwise search all filters
            for matches to the filter_id or name

        Returns:
            List of instances that match the filter_id or name parameters
        """

        assert filter_id is None or name is None

        # TODO: Be sure this one is in general validate.
        if owned:
            assert name is None

        insts = []
        filters = self.get_filters(owned)

        # TODO: do list comprehension here.
        if filter_id:
            for filter in filters:
                if self.get_filter_id(filter.path) == filter_id:
                    insts.append(filter)
            filters = insts
        elif name:
            for filter in filters:
                if filter['Name'] == name:
                    insts.append(filter)
            filters = insts

        return filters

    def err_msg(self, text, er):
        """
        Create a text message from the inputs
        """
        return "{}: Subscription mgr id: {}, server id: {}, Exception: {}: {}" \
               .format(text, self.submgr, self.server_id,
                       er.__class__.__name__, er)


#
#   Common functions for this command
#
def display_inst_nonnull_props(context, options, instances, output_format):
    """
    Display the instances defined in instances after removing any properties
    that are Null for all instances.
    """
    pl = None
    # Create a dictionary of all properties that have non-null values
    pldict = {}  # make this Nocasedict
    for inst in instances:
        for name, prop in inst.properties.items():
            if prop.value:
                pldict[name] = True
    pl = list(pldict.keys())

    display_cim_objects(context, instances, output_format,
                        summary=options['summary'], sort=True,
                        property_list=pl)


def pick_path(context, paths, msg):
    """
    Pick one instance path from instances and return
    """
    try:
        return pick_one_from_list(context, sort_cimobjects(paths), msg)
    except ValueError as exc:
        raise click.ClickException(str(exc))


def validate_url(url, default_scheme='http', default_host='localhost'):
    """
    Parse and validate url. This allows replacing missing components for
    scheme and host with predefined values.

    Parameters:

      url(:term:`string`):
        String containing scheme, host and port url components

      default_scheme:

      default_host:

    Returns:
      String containing the url with any default component replacements

    Raises:
        ClickException if the url is invalid for any of multiple reasons.
    """
    try:
        url = urlparse(url)
        if not url.scheme:
            url._replace(scheme=default_scheme)
        if url.scheme not in ["http", "https"]:
            raise click.ClickException("Invalid url. scheme {} not allowed".
                                       format(url.scheme))
        if not url.hostname:
            url._replace(host=default_host)
        try:
            if url.port is None:
                raise click.ClickException("Invalid url. port required.")
        except ValueError as er:
            raise click.ClickException("Invalid port {} in  {}".format(url.port,
                                                                       er))

        # Test if any other elements exist, specifically the path
        if url.path:
            raise click.ClickException("Invalid URL contains path component: "
                                       "{}".format(url))

    except Exception as ex:
        raise click.ClickException("Invalid url: {}".format(ex))

    return url.geturl()


#####################################################################
#
#  Command functions for each of the subcommands in the subscription group
#
#####################################################################


def cmd_subscription_list(context, options):
    """
    Display overview information on the subscriptions, filters and indications
    """
    output_format = validate_output_format(context.output_format,
                                           ['CIM', 'TABLE'],
                                           default_format="table")
    csm = CmdSubscriptionManager(context, options)

    all_subscriptions = csm.get_subscriptions(ALL)
    all_destinations = csm.get_destinations(ALL)
    all_filters = csm.get_filters(ALL)

    owned_subscriptions = csm.get_subscriptions(OWNED)
    owned_destinations = csm.get_destinations(OWNED)
    owned_filters = csm.get_filters(OWNED)

    if options['summary']:
        context.spinner_stop()
        click.echo("{} subscriptions, {} filters, {} destinations".
                   format(len(all_subscriptions), len(all_filters),
                          len(all_destinations)))
        return

    headers = ['CIM_class', 'owned', 'not_owned', 'all']

    rows = []
    rows.append(["CIM_IndicationSubscription",
                 len(owned_subscriptions),
                 len(all_subscriptions) - len(owned_subscriptions),
                 len(all_subscriptions)])
    rows.append(["CIM_IndicationFilter",
                 len(owned_filters),
                 len(all_filters) - len(owned_filters),
                 len(all_filters)])
    rows.append(["CIM_IndicationFilter",
                 len(owned_destinations),
                 len(all_destinations) - len(owned_destinations),
                 len(all_destinations)])

    title = "WBEM server indication instances for server_id {}". \
        format(csm.server_id)

    if output_format_is_table(output_format):
        click.echo(format_table(rows, headers, title=title,
                   table_format=output_format))

    else:
        for row in rows:
            click.echo("{}: {}, {}, {}". format(row[0], row[1], row[2],
                                                row[3]))


def cmd_subscription_list_subscriptions(context, options):
    """
    Display the list of indication subscriptions on the defined server.
    """
    output_format = validate_output_format(context.output_format,
                                           ['CIM', 'TABLE'],
                                           default_format="table")
    csm = CmdSubscriptionManager(context, options)

    owned = options['owned']

    svr_subscriptions = csm.get_subscriptions(owned)
    svr_destinations = csm.get_destinations(owned)
    svr_filters = csm.get_filters(owned)

    if options['detail'] or options['summary']:
        context.spinner_stop()
        display_cim_objects(context, svr_subscriptions,
                            output_format=context.output_format)
        return

    # otherwise show details of subscriptions, filters, and destinations
    # dest_dict = {dest.path: dest for dest in svr_destinations}
    # filter_dict = {filter.path: filter for filter in svr_filters}

    # TODO order these by subscription rather than type.
    inst_list = []
    if output_format_is_cimobject(output_format):
        for subscription in svr_subscriptions:
            inst_list.append(subscription)
            for filter in svr_filters:
                if subscription['Filter'] == filter.path:
                    inst_list.append(filter)
            for dest in svr_destinations:
                if subscription['Handler'] == dest.path:
                    inst_list.append(dest)
        context.spinner_stop()
        display_cim_objects(context, inst_list,
                            output_format=context.output_format)
        return

    if output_format_is_table(output_format):
        context.spinner_stop()
        # display_inst_nonnull_props(context, options, svr_subscriptions,
        #                           output_format)
        headers = ['Destination', 'Filter', 'Query\nlanguage', 'Start']
        rows = []
        for subscription in svr_subscriptions:
            row = [subscription['Filter'], subscription['Handler'],
                   subscription['SubscriptionStartTime']]
            rows.append(row)
        title = "Subscriptions"
        click.echo(format_table(rows, headers, title=title,
                   table_format=output_format))

    context.spinner_stop()
    for subscription in svr_subscriptions:
        filter_path = subscription['Filter']
        dest_path = subscription['Handler']
        click.echo("{}\n  filter: {}\n dest: {}".format("Subscription",
                                                        filter_path,
                                                        dest_path))


def cmd_subscription_send_test_indication(context, options):
    """
    Executes the code to generate test indications from a server.  This
    is specific to OpenPegasus. This function always creates owned
    destinations, filters, and subscriptions and will use existing
    objects if they exist.
    """
    TEST_CLASS = 'Test_IndicationProviderClass'
    TEST_CLASS_NAMESPACE = 'test/TestProvider'
    TEST_QUERY = 'SELECT * from {}'.format(TEST_CLASS)

    csm = CmdSubscriptionManager(context, options)

    listener_url = options['listener_url']

    # Create a listener if one does not already exist.
    dest = csm.add_listener_destinations([listener_url], owned=True)

    # Create a n indication filter and subscribe for it
    # This is specific to OpenPegasus and even to a specific
    # namespace.
    filter_id = 'pegasus_test_indication'

    filter_ = csm.find_find_matching_filters_filter(filter_id)

    # Sort out issue of multiple filterid elements.
    if filter_:
        filter_ = filter_[0]

    if not filter_:
        filter_ = csm.add_filter(TEST_CLASS_NAMESPACE,
                                 TEST_QUERY,
                                 query_language="DMTF:CQL",
                                 filter_id=filter_id,
                                 owned=True)

    if context.verbose:
        click.echo("Filter created. path {}".format(filter_.path))

    csm.add_subscriptions(filter_.path, destination_paths=dest.path, owned=True)

    if context.verbose:
        click.echo("Test indication subscription added: destination={}, "
                   "filter_id={}".format(listener_url, filter_.path))

    # Send an invokemethod to the WBEM server to initiate the indication
    # output.  This is a pegasus specific operation. Note also that the
    # way Pegasus works today, often the response for this request does not
    # get returned until well after the indication flow has started because
    # it operates on the same thread as the response.
    try:
        # Send method to pegasus server to create  required number of
        # indications. This is a pegasus specific class and method
        conn = context.pywbem_server.conn
        test_class = CIMClassName(TEST_CLASS, namespace=TEST_CLASS_NAMESPACE)
        result = conn.InvokeMethod("SendTestIndicationsCount", test_class,
                                   [('indicationSendCount',
                                     Uint32(options['count']))])

        if result[0] != 0:
            print('SendTestIndicationCount Method error. Nonzero return=%s'
                  % result[0])
            raise click.ClickException("Send Invoke method failed")

        if context.verbose:
            click.echo("Indications requested")

    except Error as er:
        print('Error: Indication Method exception %s' % er)
        raise click.ClickException("Send Invoke method failed. Exception: {}".
                                   format(er))

    click.echo("Test indications initiated.")


def cmd_subscription_remove_subscription(context, options):
    """
    Remove an indication subscription.
    """
    csm = CmdSubscriptionManager(context, options)

    if options['path']:
        instance_path = options['path']

    owned = options['owned']

    if options['select']:
        subscriptions = csm.get_subscriptions(owned)
        paths = [inst.path for inst in subscriptions]
        instance_path = pick_path(context, paths, 'Pick instance to delete.')

        csm.remove_subscriptions(instance_path)

    else:
        click.echo("path or select option required.")


def cmd_subscription_list_filters(context, options):
    """
    List the subscription filters found in the current SubscriptionManager
    object
    """
    output_format = validate_output_format(context.output_format,
                                           ['CIM', 'TABLE'],
                                           default_format="table")
    csm = CmdSubscriptionManager(context, options)

    validate_filterid_and_name(options, False)

    filter_id = options['filter_id']
    name = options['name']
    owned = options['owned']

    # TODO: Can we build this into the valid_filterid...
    if owned and name:
        raise click.ClickException("The options --owned and --name are"
                                   "mutually exclusive and cannot be used in "
                                   "the same command.")

    filters = csm.find_matching_filters(filter_id, name, owned)

    if options['detail'] and options['summary']:
        raise click.ClickException("The details and summary options are "
                                   "mutually exclusive")
    if filters:
        if output_format_is_cimobject(output_format):
            if options['detail'] or options['summary']:
                display_cim_objects(context, filters, output_format,
                                    options['summary'])
            else:
                display_inst_nonnull_props(context, options, filters,
                                           output_format)

        elif output_format_is_table(output_format):
            if options['detail']:
                properties = ['CreationclassName', 'SystemCreationClassName',
                              'SystemName', 'Name', 'Query', 'QueryLanguage',
                              'SourceNamespace']
            else:
                properties = ['Name', 'Query', 'QueryLanguage',
                              'SourceNamespace']

            display_cim_objects(context, filters, output_format,
                                property_list=properties)

        elif options['paths']:
            paths = [inst.path for inst in filters]
            display_cim_objects(context, paths, output_format,
                                options['summary'])

        elif options['detail'] or options['summary']:
            display_cim_objects(context, filters, output_format,
                                options['summary'])
        else:
            display_inst_nonnull_props(context, options, filters, output_format)

    else:
        if context.verbose:
            filter_des = ". filter_id={}".format(filter_id) if filter_id else ""
            name_des = "name={}".format(name) if name else ""
            click.echo("No matching filters for server_id={}{}{} "
                       "owned{}".format(csm.server_id, filter_des, name_des,
                                        owned))


def cmd_subscription_list_destinations(context, options):
    """
    List the subscription destinations objects found on the current connection.

    Since these are complex objects there are a variety of display options
    including table, CIM objects, etc.
    """
    output_format = validate_output_format(context.output_format,
                                           ['CIM', 'TABLE'],
                                           default_format="table")
    csm = CmdSubscriptionManager(context, options)

    destinations = csm.get_destinations(options['owned'])

    if options['summary'] and options['detail']:
        click.ClickException("The options 'summary' and 'detail' conflict.")

    detail = options['detail']

    if options['paths']:
        paths = [inst.path for inst in destinations]
        context.spinner_stop()
        display_cim_objects(context, paths, output_format,
                            options['summary'])
        return

    if output_format_is_table(output_format):
        if detail:
            properties = ['CreationclassName', 'SystemCreationClassName',
                          'SystemName', 'Name', 'Destination',
                          'PersistenceType', 'protocol']
        else:
            properties = ['Name', 'Destination', 'PersistenceType']

        context.spinner_stop()
        display_cim_objects(context, destinations, output_format,
                            sort=False, property_list=properties)

    elif output_format_is_cimobject:
        context.spinner_stop()
        if detail or options['summary']:
            display_cim_objects(context, destinations, output_format,
                                summary=options['summary'], sort=True)
        else:
            display_inst_nonnull_props(context, options, destinations,
                                       output_format)


def cmd_subscription_destination_remove_subscription(context, options):
    """
    Remove a subscription object from the server. Note that the
    SubscriptionManager may also remove filter and destination objects.
    """
    csm = CmdSubscriptionManager(context, options)

    if options['path']:
        instance_path = options['path']

    owned = options['owned']

    if options['select']:
        destinations = csm.get_subscriptions(owned)
        paths = [inst.path for inst in destinations]
        try:
            instance_path = pick_path(
                context, paths, 'Pick instance to delete.')
        except ValueError as exc:
            raise click.ClickException(str(exc))
        try:
            csm.remove_subscriptions(instance_path)
        except Error as er:
            raise click.ClickException("Delete of instance {} failed. "
                                       "Exception: {}"
                                       .format(instance_path, er))


def cmd_subscription_remove_destination(context, options):
    """
    Remove a destination object from the server
    """
    csm = CmdSubscriptionManager(context, options)

    if options['select']:
        destinations = csm.get_destinations(ALL)
        paths = [inst.path for inst in destinations]
        try:
            instance_path = pick_one_from_list(
                context, sort_cimobjects(paths), 'Pick destination to delete.')
        except ValueError as exc:
            raise click.ClickException(str(exc))
        try:
            csm.remove_destinations(instance_path)
        except Error as er:
            raise click.ClickException("Delete of instance {} failed. "
                                       "Exception: {}"
                                       .format(instance_path, er))

    else:
        click.echo("path or select option required.")


def pick_filter_to_remove(csm, context, filter_instances):
    """
    Prompts the user with a list of filter paths for a filter to remove
    """
    paths = [inst.path for inst in filter_instances]
    picked_path = pick_path(context, paths, 'Pick filter to remove.')
    csm.remove_filter(picked_path)


def validate_filterid_and_name(options, required):
    """
    Filter_id and option are mutually exclusive but Click does not directly
    support mutually exclusive options. On some commands at least one of
    them is required. On others both are optional.

    Parameters:
        options:

        required (:class:`py:bool`):
            If True, test that at least one of filter__id and name exist.
            If not True, they are both optional.

    Returns:
        Returns only if the filter_id and name parameters are valid

    Raises:
        click.ClickException if the combination is not valid.
    """
    if required:
        if options['filter_id'] is None and options['name'] is None:
            raise click.ClickException(
                "The filter_id and name parameters are both None, but "
                "exactly one of them must be specified")
    if options['filter_id'] is not None:
        if options['name'] is not None:
            raise click.ClickException("The filter_id and name parameters "
                                       "are both specified, but only one of "
                                       "them must be specified")

    if options['name'] and options['owned']:
        raise click.ClickException("Name parameter not allowed with owned "
                                   "filters")


####################################################################
#
#   Subscription command action functions.
#
####################################################################

def cmd_subscription_remove_filter(context, options):
    """
    Remove a single indication filter found by the get_all_filters
    method.
    """
    csm = CmdSubscriptionManager(context, options)

    # Validate that both do not exist. Neither is required
    validate_filterid_and_name(options, False)

    filter_id = options['filter_id']
    filter_name = options['name']
    owned = options['owned']

    # TODO: Should this be in validate also
    if owned and filter_name:
        raise click.ClickException("The options --owned and --name are"
                                   "mutually exclusive and cannot be used in "
                                   "the same command.")

    # If select, pick filters that match including optionally filtering by
    # filter_id or name.
    if options['select']:
        if filter_id:
            filters = csm.find_matching_filters(filter_id,
                                                filter_name, owned)
        else:
            filters = csm.get_filters()
        pick_filter_to_remove(csm, context, filters)
        return

    # TODO combine the following two ifs.
    if filter_id:
        filters = csm.find_matching_filters(filter_id,
                                            filter_name, owned)
        if len(filters) > 1:
            click.echo('filter_id "{0}" returns multiple filters'.
                       format(filter_id))
            # TODO: separate pick from remove
            pick_filter_to_remove(filters)
            return
        if not filters:
            click.echo("No filters found with filter_id: {}". format(filter_id))
            return
        csm.remove_filter(filters[0].path)
        return

    if filter_name:
        filters = csm.get_all_filters()
        found_filters = []
        for filter in filters:
            if filter['Name'] == filter_name:
                found_filters.append(filter)
        if not found_filters:
            click.echo("Filter name: {} not found.".format(filter_name))
            return
        if len(found_filters) == 1:
            csm.remove_filter(found_filters[0].path)
            return
        click.echo('filter_id "{0}" returns multiple filters'.
                   format(filter_id))
        # TODO separate pick from remove
        pick_filter_to_remove(csm, context, filters)
        return

    else:
        raise click.ClickException("Select option, filter_id or name option "
                                   "required.")


def cmd_subscription_add_filter(context, options):
    """
    Add a filter defined by the input parameters to the target server.
    """
    csm = CmdSubscriptionManager(context, options)

    validate_filterid_and_name(options, True)

    source_namespace = options['source_namespace'] or \
        context.pywbem_server.conn.default_namespace

    try:
        inst = csm.add_filter(source_namespace,
                              options['query'],
                              query_language=options['query_language'],
                              owned=options['owned'],
                              filter_id=options['filter_id'],
                              name=options['name'])
        if context.verbose:
            click.echo("Returned Instance:\n{}".format(inst.tomof()))

    except ValueError as ve:
        raise click.ClickException(
            csm.err_msg("Add filter failed. Parameter error", ve))
    except Error as er:
        raise click.ClickException(csm.err_msg("Add filter failed", er))


def cmd_subscription_add_destinations(context, options):
    """
    Add a single listener definition.
    """
    csm = CmdSubscriptionManager(context, options)

    listener_urls = [validate_url(url) for url in options['listener_url']]

    paths = csm.add_listener_destinations(listener_urls, options['owned'])

    if context.verbose:
        click.echo("Added {}".format("\n".join(str(paths))))


def cmd_subscription_add_subscription(context, options):
    """
    Add a single subscription based on selecting a filter and destination.
    """
    csm = CmdSubscriptionManager(context, options)

    if options['select']:
        filters = csm.get_filters(ALL)
        fpaths = [inst.path for inst in filters]
        indication_filter = pick_path(context, fpaths,
                                      'Pick filter to use for subscription.')

        destinations = csm.get_destinations(ALL)
        dpaths = [inst.path for inst in destinations]
        dest = pick_path(context, dpaths,
                         'Pick destination to use for subscription.')
        csm.add_subscriptions(indication_filter, dest)

    else:
        raise click.ClickException("Use select for now")


def cmd_subscription_remove_servers(context, options):
    """
    Remove the server_id which also unregisters listener destinations and
    removes all owned destinations, filters, and subscriptions.
    """
    csm = CmdSubscriptionManager(context, options)

    # TODO: Why are we doing the gets here
    csm.get_filters(ALL)
    csm.get_destinations(ALL)
    csm.get_subscriptions(ALL)
    csm.remove_server()
