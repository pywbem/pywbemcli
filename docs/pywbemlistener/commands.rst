..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..    http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.
..


.. _`Pywbemlistener commands`:

Pywbemlistener commands
=======================

This section describes each of the pywbemlistener commands including examples.

The pywbemlistener commands are:

* :ref:`pywbemlistener list command` - List the currently running named WBEM indication listeners.
* :ref:`pywbemlistener show command` - Show a named WBEM indication listener.
* :ref:`pywbemlistener start command` - Start a named WBEM indication listener in the background.
* :ref:`pywbemlistener stop command` -  Stop a named WBEM indication listener.
* :ref:`pywbemlistener test command` -  Send a test indication to a named WBEM indication listener.
* :ref:`pywbemlistener run command` - Run as a named WBEM indication listener.


.. _`pywbemlistener list command`:

``pywbemlistener list`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener list`` command lists the currently running WBEM indication
listeners on the local system. They are identified as the processes executing
the ``pywbemlistener run`` command.

Example:

.. code-block:: text

    $ pywbemlistener list
    +--------+--------+----------+-------+---------------------+
    | Name   |   Port | Scheme   |   PID | Created             |
    |--------+--------+----------+-------+---------------------|
    | lis1   |  25989 | https    | 59327 | 2021-07-03 15:31:55 |
    +--------+--------+----------+-------+---------------------+

The ``-o, --output-format`` general option can be used to control the format of
the table that is displayed, for example:

Example:

.. code-block:: text

    $ pywbemlistener -o rst list
    ======  ======  ========  =====  ===================
    Name      Port  Scheme      PID  Created
    ======  ======  ========  =====  ===================
    lis1     25989  https     59327  2021-07-03 15:31:55
    ======  ======  ========  =====  ===================

See :ref:`pywbemlistener list --help` for the exact help output of the command.


.. _`pywbemlistener show command`:

``pywbemlistener show`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener show`` command shows details of a specific running WBEM
indication listener on the local system, by specifying the listener name.

The running listeners are identified as the processes executing the
``pywbemlistener run`` command. The listener name is also identified from
the process command line.

Example:

.. code-block:: text

    $ pywbemlistener show lis1
    +--------------------+---------------------------+
    | Attribute          | Value                     |
    |--------------------+---------------------------|
    | Name               | lis1                      |
    | Port               | 25989                     |
    | Scheme             | https                     |
    | Certificate file   | .../certs/server_cert.pem |
    | Key file           | .../certs/server_key.pem  |
    | Indication call    |                           |
    | Indication display | False                     |
    | Indication file    |                           |
    | Log file           |                           |
    | PID                | 59327                     |
    | Created            | 2021-07-03 15:31:55       |
    +--------------------+---------------------------+

See :ref:`pywbemlistener show --help` for the exact help output of the command.


.. _`pywbemlistener start command`:

``pywbemlistener start`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener start`` command starts a new WBEM indication listener on
the local system.

The listener is running as a normal user process in the background, inheriting
the group and user context from the process that runs the ``pywbemlistener start``
command (usually the shell process in a terminal session).

Example:

.. code-block:: text

    $ pywbemlistener start lis1 --cert-file .../certs/server_cert.pem --key-file .../certs/server_key.pem
    Running listener lis1 at https://localhost:25989

The previous example started a listener for HTTPS (the default) on the default
port 25989. Because HTTPS was used, it was necessary to specify an X.509 server
certificate and its key file.

The port can be specified using the ``-p, --port`` option.
The use of HTTP instead of the default HTTPS can be used by specifying it with
the ``-s, --scheme`` option.

When the listener receives an indication, by default it drops it and does nothing
else.

The following actions can be configured to be performed on each received
indication. Multiple actions can be specified.

* Appending it as a line to a file:

  This action is enabled by specifying the ``--indi-file FILE`` option.

  The format of the line can be configured using the ``--indi-format FORMAT``
  option.

  ``FORMAT`` is a Python new-style format string that can use the following
  keyword args:

  * 'dt' - datetime object of the time the listener received the indication, in
    local time. The object is timezone-aware on Python 3.6 or higher.
  * 'dt_tzname' - timezone name of the datetime object if timezone-aware, else
    the empty string.
  * 'h' - Host name or IP address of the host that sent the indication
  * 'i' - pywbem.CIMInstance object with the indication instance
  * 'c' - CIM classname of the indication instance
  * 'p' - Case-insensitive dictionary of the indication properties, displayed
    as blank-separated name=value items

  The default format is: "{dt} {h} {c} {p}".

* Calling a Python function, via the ``--indi-call MODULE.FUNCTION`` option.

  ``MODULE`` must be a module name or a dotted package name in the module search
  path, e.g. 'mymodule' or 'mypackage.mymodule'.

  The current directory is added to the front of the Python module search path,
  if needed. Thus, the module can be a single module file in the current
  directory, for example:

  .. code-block:: text

      ./mymodule.py

  or a module in a package in the current directory, for example:

  .. code-block:: text

      ./mypackage/__init__.py
      ./mypackage/mymodule.py

  ``FUNCTION`` must be a function in that module with the following interface:

  .. code-block:: text

      def func(indication, host)

  Parameters:

  * 'indication' is a :class:`pywbem.CIMInstance` object representing the CIM
    indication that has been received. Its 'path' attribute is None.

  * 'host' is a string with the host name or IP address of the indication sender
    (typically a WBEM server).

  The return value of the function will be ignored.

  Exceptions raised when importing the module cause the 'pywbemlistener run'
  command to terminate with an error. Exceptions raised by the function when
  it is called cause an error message to be displayed on stderr of the listener
  process and logged, if logging is enabled.

The started WBEM indication listener can log any issues it encounters, to a file.
This is enabled by using the ``-l, --logdir DIR`` general option.

See :ref:`pywbemlistener start --help` for the exact help output of the command.


.. _`pywbemlistener stop command`:

``pywbemlistener stop`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener stop`` command stops a running WBEM indication listener on
the local system.

Example:

.. code-block:: text

    $ pywbemlistener stop lis1
    Shut down listener lis1 running at http://localhost:25989

See :ref:`pywbemlistener stop --help` for the exact help output of the command.


.. _`pywbemlistener test command`:

``pywbemlistener test`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener test`` command sends a test indication to a running WBEM
indication listener on the local system.

Example:

.. code-block:: text

    $ pywbemlistener test lis1
    Sending the following test indication:
    instance of CIM_AlertIndication {
       IndicationIdentifier = NULL;
       IndicationTime = "20210711160151.847111+000";
       AlertingElementFormat = 2;
       AlertingManagedElement = NULL;
       AlertType = 2;
       Message = "Test message";
       MessageID = "TEST0000";
       OwningEntity = "TEST";
       PerceivedSeverity = 2;
       ProbableCause = 0;
       SystemName = NULL;
       MessageArguments = { };
    };
    Sent test indication to listener lis1 at http://localhost:25989

See :ref:`pywbemlistener test --help` for the exact help output of the command.


.. _`pywbemlistener run command`:

``pywbemlistener run`` command
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``pywbemlistener run`` command runs the WBEM indication listener code
in a loop that never ends. It is possible to start this command in the
background or even run it in the foreground, but it is not recommended that
users do that directly. Instead, users should use the
:ref:`pywbemlistener start command`, which starts the ``pywbemlistener run``
command as a background process.

See :ref:`pywbemlistener run --help` for the exact help output of the command.
