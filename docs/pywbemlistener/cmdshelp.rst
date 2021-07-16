
.. _`pywbemlistener Help Command Details`:

pywbemlistener Help Command Details
===================================


This section shows the help text for each pywbemlistener command.



Help text for ``pywbemlistener``:


::

    Usage: pywbemlistener [GENERAL-OPTIONS] COMMAND [ARGS] [COMMAND-OPTIONS]

      The pywbemlistener command can run and manage WBEM listeners.

      Each listener is a process that executes the 'pywbemlistener run' command to receive WBEM indications sent from a
      WBEM server.

      A listener process can be started with the 'pywbemlistener start' command and stopped with the 'pywbemlistener stop'
      command.

      There is no central registration of the currently running listeners. Instead, the currently running processes
      executing the 'pywbemlistener run' command are by definition the currently running listeners. Because of this, there
      is no notion of a stopped listener nor does a listener have an operational status.

      The general options shown below can also be specified on any of the commands, positioned right after the
      'pywbemlistener' command name.

      The width of help texts of this command can be set with the PYWBEMTOOLS_TERMWIDTH environment variable.

      For more detailed documentation, see:

          https://pywbemtools.readthedocs.io/en/stable/

    General Options:
      -o, --output-format FORMAT  Output format for the command result. FORMAT is one of the table formats:
                                  [table|plain|simple|grid|psql|rst|html].

      -l, --logdir DIR            Enable logging of the 'pywbemlistener run' command output to a file in a log directory.
                                  The file will be named 'pywbemlistener_NAME.log' where NAME is the listener name. Default:
                                  EnvVar PYWBEMLISTENER_LOGDIR, or no logging.

      -v, --verbose               Verbosity level. Can be specified multiple times: -v: Display indication processing
                                  settings; -vv: Display interactions between start and run commands.

      --pdb                       Pause execution in the built-in pdb debugger just before executing the command within
                                  pywbemlistener. Default: EnvVar PYWBEMLISTENER_PDB, or no debugger.

      --warn                      Enable display of all Python warnings. Default: Leave warning control to the
                                  PYTHONWARNINGS EnvVar, which by default displays no warnings.

      --version                   Show the version of this command and the pywbem package.
      -h, --help                  Show this help message.

    Commands:
      list   List the currently running named WBEM indication listeners.
      show   Show a named WBEM indication listener.
      start  Start a named WBEM indication listener in the background.
      stop   Stop a named WBEM indication listener.
      test   Send a test indication to a named WBEM indication listener.
      run    Run as a named WBEM indication listener.


.. _`pywbemlistener list --help`:

pywbemlistener list --help
--------------------------



Help text for ``pywbemlistener list`` (see :ref:`pywbemlistener list command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] list [COMMAND-OPTIONS]

      List the currently running named WBEM indication listeners.

      This is done by listing the currently running `pywbemlistener run` commands.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemlistener run --help`:

pywbemlistener run --help
-------------------------



Help text for ``pywbemlistener run`` (see :ref:`pywbemlistener run command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] run NAME [COMMAND-OPTIONS]

      Run as a named WBEM indication listener.

      Run this command as a named WBEM indication listener until it gets terminated, e.g. by a keyboard interrupt, break
      signal (e.g. kill), or the `pywbemlistener stop` command.

      A listener with that name must not be running, otherwise the command fails.

      Note: The `pywbemlistener start` command should be used to start listeners, and it starts a `pywbemlistener run`
      command as a background process. Use the `pywbemlistener run` command only when you need to have control over how
      exactly the process runs in the background.

      Note: The --start-pid option is needed because on Windows, the `pywbemlistener run` command is not the direct child
      process of the `pywbemlistener start` command starting it.

      Examples:

        pywbemlistener run lis1

    Command Options:
      --start-pid PID              PID of the "pywbemlistener start" process to be notified about the startup of the run
                                   command. Default: No such notification will happen.

      -p, --port PORT              The port number the listener will open to receive indications. This can be any available
                                   port. Default: 25989

      -s, --scheme SCHEME          The scheme used by the listener (http, https). Default: https
      -c, --certfile FILE          Path name of a PEM file containing the certificate that will be presented as a server
                                   certificate during SSL/TLS handshake. Required when using https. The file may in addition
                                   contain the private key of the certificate. Default: EnvVar PYWBEMLISTENER_CERTFILE, or
                                   no certificate file.

      -k, --keyfile FILE           Path name of a PEM file containing the private key of the server certificate. Required
                                   when using https and when the certificate file does not contain the private key. Default:
                                   EnvVar PYWBEMLISTENER_KEYFILE, or no key file.

      --indi-call MODULE.FUNCTION  Call a Python function for each received indication. Invoke with --help-call for details
                                   on the function interface. Default: No function is called.

      --indi-file FILE             Append received indications to a file. The format can be modified using the --indi-format
                                   option. Default: Not appended.

      --indi-format FORMAT         Sets the format to be used when displaying received indications. Invoke with --help-
                                   format for details on the format specification. Default: "{dt} {h} {i_mof}".

      --help-format                Show help message for the format specification used with the --indi-format option and
                                   exit.

      --help-call                  Show help message for calling a Python function for each received indication when using
                                   the --indi-call option and exit.

      -h, --help                   Show this help message.


.. _`pywbemlistener show --help`:

pywbemlistener show --help
--------------------------



Help text for ``pywbemlistener show`` (see :ref:`pywbemlistener show command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] show NAME [COMMAND-OPTIONS]

      Show a named WBEM indication listener.

      A listener with that name must be running, otherwise the command fails.

      Examples:

        pywbemlistener show lis1

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemlistener start --help`:

pywbemlistener start --help
---------------------------



Help text for ``pywbemlistener start`` (see :ref:`pywbemlistener start command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] start NAME [COMMAND-OPTIONS]

      Start a named WBEM indication listener in the background.

      A listener with that name must not be running, otherwise the command fails.

      A listener is identified by its hostname or IP address and a port number. It can be started with any free port.

      Examples:

        pywbemlistener start lis1

    Command Options:
      -p, --port PORT              The port number the listener will open to receive indications. This can be any available
                                   port. Default: 25989

      -s, --scheme SCHEME          The scheme used by the listener (http, https). Default: https
      -c, --certfile FILE          Path name of a PEM file containing the certificate that will be presented as a server
                                   certificate during SSL/TLS handshake. Required when using https. The file may in addition
                                   contain the private key of the certificate. Default: EnvVar PYWBEMLISTENER_CERTFILE, or
                                   no certificate file.

      -k, --keyfile FILE           Path name of a PEM file containing the private key of the server certificate. Required
                                   when using https and when the certificate file does not contain the private key. Default:
                                   EnvVar PYWBEMLISTENER_KEYFILE, or no key file.

      --indi-call MODULE.FUNCTION  Call a Python function for each received indication. Invoke with --help-call for details
                                   on the function interface. Default: No function is called.

      --indi-file FILE             Append received indications to a file. The format can be modified using the --indi-format
                                   option. Default: Not appended.

      --indi-format FORMAT         Sets the format to be used when displaying received indications. Invoke with --help-
                                   format for details on the format specification. Default: "{dt} {h} {i_mof}".

      --help-format                Show help message for the format specification used with the --indi-format option and
                                   exit.

      --help-call                  Show help message for calling a Python function for each received indication when using
                                   the --indi-call option and exit.

      -h, --help                   Show this help message.


.. _`pywbemlistener stop --help`:

pywbemlistener stop --help
--------------------------



Help text for ``pywbemlistener stop`` (see :ref:`pywbemlistener stop command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] stop NAME [COMMAND-OPTIONS]

      Stop a named WBEM indication listener.

      The listener will shut down gracefully.

      A listener with that name must be running, otherwise the command fails.

      Examples:

        pywbemlistener stop lis1

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemlistener test --help`:

pywbemlistener test --help
--------------------------



Help text for ``pywbemlistener test`` (see :ref:`pywbemlistener test command`):


::

    Usage: pywbemlistener [GENERAL-OPTIONS] test NAME [COMMAND-OPTIONS]

      Send a test indication to a named WBEM indication listener.

      The indication is an alert indication with fixed properties. This allows testing the listener and what it does with
      the indication.

      Examples:

        pywbemlistener test lis1

    Command Options:
      -h, --help  Show this help message.

