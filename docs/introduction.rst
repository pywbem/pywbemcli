.. Copyright  2017 IBM Corp. and Inova Development Inc.
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


.. _`Introduction`:

Introduction
============

.. _`Pywbemtools Features`:

Pywbemtools features
--------------------

Pywbemtools is a collection of command line tools that communicate with WBEM
Servers. The tools are written in pure Python and support Python 2 and Python
3.

Pywbemtools provides a command line tool (pywbemcli) that uses the pywbem
Python WBEM client infrastructure to issue operations to a WBEM server using
the WBEM standards defined by the DMTF to perform system management tasks.

WBEM standards are used for a wide variety of systems management tasks
in the industry including DMTF management standards and the SNIA Storage
Management Initiative Specification(SMI-S).

Pywbemtools and pywbem WBEM Client are packages in the github pywbem repository
and are released to PyPi. Pywbemcli is a module in pywbemtools.


.. _`Pywbemcli command line interface WBEM client`:

Pywbemcli command line interface WBEM client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Pywbemcli provides access to WBEM servers from the command line on multiple OS
platforms. It provides functionality to:

* Explore the CIM data of WBEM Servers. It can manage/inspect the CIM model
  components including CIM classes, CIM instances, and CIM qualifiers and execute
  CIM methods and queries on the WBEM server. It implements subcommands to
  execute the :term:`CIM-XML` operations defined in the DMTF specification CIM Operations
  Over HTTP(:term:`DSP0200`).

* Inspect/manage WBEM server functionality including:

  * CIM namespaces,
  * WBEM registered management profiles,
  * WBEM server brand information

* Capture detailed information on interactions with the WBEM server including
  time statistics.

* Maintain a file of WBEM server definitions so that pywbemcli can access
  multiple servers by name.

* Provide both a command line interface and an interactive mode where multiple
  pywbemcli commands can be executed within the context of a WBEM server.


.. _`Supported environments`:

Supported environments
----------------------

The pywbemcli module of the pywbemtools package is supported in these
environments:

* Operating systems: Linux, Windows, MacOS
* Python versions: 2.7, 3.4, and greater
* pywbem 0.13.0 or greater

.. _`Installation`:

Installation
------------

.. _virtual Python environment: http://docs.python-guide.org/en/latest/dev/virtualenvs/
.. _Pypi: http://pypi.python.org/

The easiest way to install the pywbemcli package is using Pip. Pip ensures
that any dependent Python packages also get installed.

Pip will install the packages into your currently active Python environment
(your system Python or your predefined virtual Python environment).

It is beneficial to set up a `virtual Python environment`_ for your project,
because that leaves your system Python installation unchanged, it does not
require ``sudo`` rights, and last but not least it gives you better control
about the installed packages and their versions.

Installation of latest released version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following command installs the latest released version of the pywbemctools
package from `Pypi`_ into the currently active Python environment:

.. code-block:: text

    $ pip install pywbemtools

This will download and install the latest released version of pywbemtools and
its dependent packages into your current Python environment (e.g. into your
system Python or into a virtual Python environment).

Installation of latest development version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As an alternative, if you want to install the latest development level of the
pywbemctools package for some reason, install directly from the ``master``
branch of the Git repository of the package:

.. code-block:: text

    $ pip install git+https://github.com/pywbem/pywbemtools.git@master

Verification of the installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can verify that the pywbemcli package and its dependent packages are
installed correctly by invoking:

.. code-block:: bash

    $ pywbemcli --version
    0.5.0

.. _`Deprecation policy`:

Deprecation policy
------------------

Pywbemtools attempts to be as backwards compatible as possible.

Occasionally functionality needs to be retired, because it is flawed and
a better but incompatible replacement has emerged.

In pywbemtools, such changes are done by deprecating existing functionality,
without removing it. The deprecated functionality is still supported throughout
new minor releases. Eventually, a new major release will break compatibility
and will remove the deprecated functionality.

In order to prepare users of pywbemtools for that, deprecation of functionality
is stated in the CLI documentation, and is made visible at runtime by issuing
Python warnings of type ``DeprecationWarning`` (see the Python
:mod:`py:warnings` module).

Since Python 2.7, ``DeprecationWarning`` messages are suppressed by default.
They can be shown for example in any of these ways:

* By invoking Python with the environment variable: ``PYTHONWARNINGS=default``

It is recommended that users of the pywbemtools package run their test code with
``DeprecationWarning`` messages being shown, so they become aware of any use of
deprecated functionality.

Here is a summary of the deprecation and compatibility policy used by
pywbemtools, by release type:

* New update release (M.N.U -> M.N.U+1): No new deprecations; fully backwards
  compatible.
* New minor release (M.N.U -> M.N+1.0): New deprecations may be added; as
  backwards compatible as possible.
* New major release (M.N.U -> M+1.0.0): Deprecated functionality may get
  removed; backwards compatibility may be broken.

Compatibility is always seen from the perspective of the user of pywbemtools,
so a backwards compatible new pywbemtools release means that the user can
safely upgrade to that new release without encountering compatibility issues.

Versioning
----------

This documentation applies to version |release| of the pywbemtools package. You
can also see that version in the top left corner of this page.

The pywbemtools package uses the rules of `Semantic Versioning 2.0.0`_ for its
version.

.. _Semantic Versioning 2.0.0: http://semver.org/spec/v2.0.0.html


This documentation may have been built from a development level of the
package. You can recognize a development version of this package by the
presence of a ".devD" suffix in the version string. Development versions are
pre-versions of the next assumed version that is not yet released. For example,
version 0.5.1.dev2 is development pre-version #2 of the next version to be
released after 0.5.0. Version 1.5.1 is an `assumed` next version, because the
`actually released` next version might be 0.7.0 or even 1.0.0.


.. _`Compatibility`:

Compatibility
-------------

In this package, compatibility is always seen from the perspective of the user
of the package. Thus, a backwards compatible new version of this package means
that the user can safely upgrade to that new version without encountering
compatibility issues.

This package uses the rules of `Semantic Versioning 2.0.0`_ for compatibility
between package versions, and for deprecations.

The public command line interface of this package that is subject to the
semantic versioning rules (and specificically to its compatibility rules) is
the CLI syntax described in this documentation.

The output formats are currently not the subject of compatiblity assurances.

Violations of these compatibility rules are described in section
:ref:`Change log`.


.. _`Deprecation and compatibility policy`:

Deprecation and compatibility policy
------------------------------------

Deprecated functionality is marked accordingly in this documentation and in the
:ref:`Change log`, and is made visible at runtime by issuing Python warnings of
type :exc:`~py:exceptions.DeprecationWarning` (see :mod:`py:warnings` for
details).

Since Python 2.7, :exc:`~py:exceptions.DeprecationWarning` warnings are
suppressed by default. They can be shown for example in any of these ways:


* by invoking pywbemcl with the environment variable:

  ``PYTHONWARNINGS=default``

It is recommended that users of this package run their tests with
:exc:`~py:exceptions.DeprecationWarning` warnings being shown, so they become
aware of any use of deprecated functionality.

It is even possible to cause pywbemcli to fail by setting the action to ``'error'``
instead of ``'default'``.


.. _`Reporting issues`:

Reporting issues
----------------

If you encounter any problem with this package, or if you have questions of any
kind related to this package (even when they are not about a problem), please
open an issue in the `pywbemtools issue tracker`_.

.. _pywbemtools issue tracker: https://github.com/pywbem/pywbemtools/issues


.. _`License`:

License
-------

This package is licensed under the `Apache 2.0 License`_.

.. _Apache 2.0 License: https://raw.githubusercontent.com/pywbem/pywbemtools/master/LICENSE

