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
pybemcli context object. This is the common object for click command calls for
pywbemcli context information.

It contains data that is set in the top level and used in command calls

This object is attached to the Click Context in pywbemcli.py
"""

from __future__ import absolute_import, print_function, unicode_literals

import os
import click
import click_spinner

from .._output_formatting import format_table, validate_output_format


class ContextObj(object):
    # pylint: disable=useless-object-inheritance, too-many-instance-attributes
    """
        Manage the pywbemcli context that is carried within the Click
        context object in the obj parameter. This is the object that
        communicates between the cli commands and command groups. It contains
        the information that is common to the multiple click commands
    """

    spinner_envvar = 'PYWBEMCLI_SPINNER'

    # pylint: disable=unused-argument
    def __init__(self, pywbem_server, output_format, use_pull,
                 pull_max_cnt, timestats, log, verbose, pdb,
                 warn, connections_repo, interactive_mode,
                 close_interactive_server):
        """
        Parameters:

          pywbem_server :class:`PywbemServer`):
            PywbemServer instance to be used for connection

          output_format (:term:`string or None):
            String representing the type of output from the --output-format
            general option or None if the default is to be used.

          use_pull (:class:`py:bool` or None):
            If boolean defines whether pull operations are to be used.  If
            None, the pywbem client will decide.           `

          pull_max_cnt(:term:`integer`):
            Positive integer represenging the max size of each pull
            operation response

          timestats (:class:`py:bool`):
            See timestats general option

          log (:term:`string or None):
            String defining the characteristics of log output for each
            WBEM operation or None if logging is disabled.

          verbose (:class:`py:bool`):
            See verbose general option

          pdb (:class:`py:bool`):
            See pdb general option

          warn (:class:`py:bool`):
            See warn general option

          connections_repo:

          interactive_mode (:class:`py:bool`):
            If True, pywbemcli is in interactive mode.

          close_interactive_server (:class:`py:bool`):
            Flag that defines interactive command with a server definition
            that must be disconnected after the command

        """

        self._pywbem_server = pywbem_server
        self._output_format = output_format
        self._use_pull = use_pull
        self._pull_max_cnt = pull_max_cnt
        self.timestats = timestats   # has setter method
        self._log = log
        self._verbose = verbose
        self._pdb = pdb
        # warn included only to insure that original cmd line input flag
        # maintained through interactive session.
        self._warn = warn
        self._connections_repo = connections_repo
        self.interactive_mode = interactive_mode
        self._close_interactive_server = close_interactive_server

        self._spinner_enabled = None  # Deferred init in getter
        self._spinner_obj = click_spinner.Spinner()

    def __repr__(self):
        return 'ContextObj(at {:08x}, pywbem_server={!r}, outputformat={}, ' \
               'use_pull={}, pull_max_cnt={}, timestats={}, log={}, ' \
               'verbose={}, spinner_enabled={}, interactive_mode={}' \
               .format(id(self), self._pywbem_server, self.output_format,
                       self.use_pull, self.pull_max_cnt, self.timestats,
                       self.log, self.verbose, self.spinner_enabled,
                       self._interactive_mode)

    @property
    def output_format(self):
        """
        :term:`string`: String defining the output format requested.  This may
        be None meaning that the default format should be used or may be
        one of the values in the TABLE_FORMATS variable.
        """
        return self._output_format

    @property
    def timestats(self):
        """
        :term:`string`: Output format to be used.
        """
        return self._timestats

    @timestats.setter
    def timestats(self, value):
        """Setter method; for a description see the getter method."""
        # pylint: disable=attribute-defined-outside-init
        self._timestats = value

    @property
    def interactive_mode(self):
        """
        :class:`py:bool`: 'True' if in interactive mode and 'False' if
        in the command mode.
        """
        return self._interactive_mode

    @interactive_mode.setter
    def interactive_mode(self, mode):
        """Setter method; for a description see the getter method."""
        assert isinstance(mode, bool)
        # pylint: disable=attribute-defined-outside-init
        self._interactive_mode = mode

    @property
    def use_pull(self):
        """
        :term:`string`: Choice of whether pull, traditional or either type
        of operation is to be used for the instance enumerates, references,
        or associator commands.
        """
        return self._use_pull

    @property
    def pull_max_cnt(self):
        """
        :term:`string`: Maximum number of objects to be returne for pull op.
        """
        return self._pull_max_cnt

    @property
    def log(self):
        """
        :term:`string`: log definition from cmd line
        """
        return self._log

    @property
    def pdb(self):
        """
        bool: Indicates whether to break in the debugger.
        """
        return self._pdb

    @property
    def warn(self):
        """
        bool: Indicates whether to enable Python warnings.
        """
        return self._warn

    @property
    def connections_repo(self):
        """
        :class:`ConnectionRepository` instance defining at least the filename
        of the Connections repository. The connections_repo may not be
        loaded at this point.
        """
        return self._connections_repo

    def is_connected(self):
        """
        bool: Indicates whether currently connected to a WBEM server. Where
        connected implies both the existence of the PywbemServer instance
        and that the connection to a server has been made.

        That is the case as soon as commands have been executed that
        communicate with the server.
        """
        return self._pywbem_server and self._pywbem_server.connected

    @property
    def pywbem_server(self):
        """
        :class:`PywbemServer`: Current PywbemServer object for this context.

        Return the PywbemServer object if it already exists.

        If the pywbem_server attribute does not exist, generate a click
        exception. If no server is specified, `None` is returned.

        This attribute is settable.
        """
        if self._pywbem_server:
            return self._pywbem_server

        ctx = click.get_current_context()
        if ctx.parent:
            ctx = ctx.parent
        cmd = "{} {}".format(ctx.info_name or "",
                             ctx.invoked_subcommand or "")
        raise click.ClickException(
            'No  current server for command "{}" that requires a WBEM server. '
            'Specify a server with the "--server", "--mock-server", or"--name" '
            'general option, by setting the corresponding environment '
            'variables, or in interactive mode '
            'use "connection select" to define a target server'.
            format(cmd))

    @pywbem_server.setter
    def pywbem_server(self, value):
        """Setter method; for a description see the getter method."""
        # pylint: disable=attribute-defined-outside-init
        self._pywbem_server = value

    @property
    def spinner_enabled(self):
        """
        :class:`py:bool`: Indicates and controls whether the spinner is enabled.

        If the spinner is enabled, subcommands will display a spinning wheel
        while waiting for completion.

        This attribute can be modified.

        The initial state of the spinner is enabled, but it can be disabled by
        setting the {0} environment variable to 'false', '0', or the empty
        value.
        """.format(self.spinner_envvar)

        # Deferred initialization
        if self._spinner_enabled is None:
            value = os.environ.get(self.spinner_envvar, None)
            if value is None:
                # Default if not set
                self._spinner_enabled = True
            elif value == '0' or value == '' or value.lower() == 'false':
                self._spinner_enabled = False
            else:
                self._spinner_enabled = True

        return self._spinner_enabled

    @spinner_enabled.setter
    def spinner_enabled(self, enabled):
        """Setter method; for a description see the getter method."""
        # pylint: disable=attribute-defined-outside-init
        self._spinner_enabled = enabled

    def spinner_start(self):
        """
        Start the spinner, if the spinner is enabled.
        """
        if self.spinner_enabled:
            self._spinner_obj.start()

    def spinner_stop(self):
        """
        Stop the spinner, if the spinner is enabled.
        """
        if self.spinner_enabled:
            self._spinner_obj.stop()

    @property
    def verbose(self):
        """
        :bool:` '~click.verbose.
        """
        return self._verbose

    def pywbem_server_exists(self):
        """
        Return True if a pywbem_server is defined.  This method allows testing
        for the existence of a PywbemServer object without causing an exception.
        The normal method is to simply access the property. In that case,
        an exception will be generated if there is no PywbemServer defined.

        Returns:
            :class": `boolean True if an instance of PywbemServer is defined.
        """
        return self._pywbem_server is not None

    def execute_cmd(self, cmd):
        """
        Call the cmd executor defined by cmd with the spinner. If the
        WBEM server object has not been created it is created so that this WBEM
        server can be used for interactive commands.

        This method is called by every command execution to setup and
        execute the command. Thus, each command definition MUST have the line
        similar to:

        context.execute_cmd(lambda: cmd_instance_query(context, query, options))
        """
        # Env.var PYWBEMCLI_DIAGNOSTICS turns on diagnostic prints for developer
        # use and is therefore not documented.
        if os.getenv('PYWBEMCLI_DIAGNOSTICS'):
            ctx = click.get_current_context()
            click.echo('DIAGNOSTICS-CMD: info_name={!r}, subcommand={!r}, '
                       'command={!r}, params={!r}'.
                       format(ctx.info_name, ctx.invoked_subcommand,
                              ctx.command,
                              ctx.params))
            display_click_context_parents(display_attrs=True)

        if not self.pdb:
            self.spinner_start()
        try:
            if self.pdb:
                import pdb  # pylint: disable=import-outside-toplevel
                pdb.set_trace()  # pylint: disable=no-member

            cmd()  # The pywbemcli command function call.

        finally:
            if not self.pdb:
                self.spinner_stop()

            # Issue statistics if requested and if the command used a conn.
            if self.timestats and self.is_connected():
                context = click.get_current_context()
                click.echo(self.format_statistics(
                    self.pywbem_server.conn.statistics, context.obj))

            # Close any existing connection if in command mode or if the
            # close_interactive_server flag is set
            if not self.interactive_mode or self._close_interactive_server:
                if self.is_connected():
                    self.pywbem_server.disconnect()

    def format_statistics(self, statistics, context):
        # pylint: disable=no-self-use
        """
        Table formatted output of client statistics
        """
        output_fmt = validate_output_format(context.output_format, 'TABLE')

        snapshot = sorted(statistics.snapshot(),
                          key=lambda item: item[1].avg_time,
                          reverse=True)

        header = ['Operation', 'Count', 'Errors',
                  'Client Time\n[ms]',
                  'Server Time\n[ms]',
                  'Request Size\n[B]',
                  'Response Size\n[B]']

        rows = []
        for name, stats in snapshot:
            row = [name, stats.count, stats.exception_count,
                   '{:.3f}'.format(stats.avg_time * 1000),
                   '{:.3f}'.format(stats.avg_server_time * 1000),
                   '{:.0f}'.format(stats.avg_request_len),
                   '{:.0f}'.format(stats.avg_reply_len)]
            rows.append(row)

        click.echo(format_table(
            rows, header, title='Client statistics',
            table_format=output_fmt))

    @staticmethod
    def update_root_click_context(ctx_obj):
        """
        Method to update the click root context with a new context
        object.  This makes the values in this context universal for all
        future commands within an interactive session.
        This is a static method and gets the current click context and
        root context from click itself.
        """
        ctx = click.get_current_context()
        root = ctx.find_root()
        root.obj = ctx_obj


#
#   Debug tools to help understanding the click context.  These are only
#   to help analyzing the click_context (ctx) and primarily in the
#   interactive mode when several levels of click context can exist
#
def display_click_context(ctx, msg=None, display_attrs=True):
    """
    Debug function displays attributes of click context
    This is a diagnostic for developer use
    """

    attrs = vars(ctx)
    if not msg:
        msg = "CLICK_CONTEXT"
    if not display_attrs:
        click.echo(ctx.obj)
    else:
        click.echo('{0} {1}, attrs:\n    {2}'.format(
            msg, ctx,
            '\n    '.join(
                '{0}: {1}'.format(i, v)
                for (i, v) in sorted(attrs.items()))))


def display_click_context_parents(display_attrs=False):
    """
    Display the current click context and its all of its parents.
    This is a diagnostic for developer use
    """
    ctx = click.get_current_context()
    disp_ctx = ctx
    # display in context top-down order
    stack = []
    # Create list of ctx parents
    while disp_ctx is not None:
        stack.append(disp_ctx)
        disp_ctx = disp_ctx.parent

    # pop off of stack to get reverse order
    level = 0
    while stack:
        disp_ctx = stack.pop()
        display_click_context(
            disp_ctx, msg='DIAGNOSTICS-CTX: Context at parent level {}:'.
            format(level), display_attrs=display_attrs)
        level += 1
