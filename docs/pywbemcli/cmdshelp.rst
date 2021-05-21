
.. _`pywbemcli Help Command Details`:

pywbemcli Help Command Details
==============================


This section shows the help text for each pywbemcli command group and command.



Help text for ``pywbemcli``:


::

    Usage: pywbemcli [GENERAL-OPTIONS] COMMAND [ARGS] [COMMAND-OPTIONS]

      Pywbemcli is a command line WBEM client that uses the DMTF CIM-XML protocol to communicate with WBEM servers.
      Pywbemcli can:

      * Manage the information in WBEM servers CIM objects using the
        operations defined in the DMTF specification.  It can manage CIM
        classes, CIM instances and CIM qualifier declarations in the WBEM
        Server and execute CIM methods and queries on the server.

      * Inspect WBEM server characteristics including namespaces, registered
        profiles, and other server information.

      * Capture detailed information on communication with the WBEM
        server including time statistics and logs of the operations.

      * Maintain a persistent list of named connections to WBEM servers
        and execute operations on them by name.

      Pywbemcli implements command groups and commands to execute the CIM-XML operations defined by the DMTF CIM
      Operations Over HTTP specification (DSP0200).

      The general options shown below can also be specified on any of the commands, positioned right after the 'pywbemcli'
      command name.

      The width of help texts of this command can be set with the PYWBEMTOOLS_TERMWIDTH environment variable.

      For more detailed documentation, see:

          https://pywbemtools.readthedocs.io/en/stable/

    General Options:
      -n, --name NAME                 Use the WBEM server defined by the WBEM connection definition NAME. This option is
                                      mutually exclusive with the --server and --mock-server options, since each defines a
                                      WBEM server. Default: EnvVar PYWBEMCLI_NAME, or none.

      -m, --mock-server FILE          Use a mock WBEM server that is automatically created in pywbemcli and populated with
                                      CIM objects that are defined in the specified MOF file or Python script file. The
                                      files may be specified with relative or absolute path.See the pywbemcli documentation
                                      for more information. This option may be specified multiple times, and is mutually
                                      exclusive with the --server and --name options, since each defines a WBEM server.
                                      Default: EnvVar PYWBEMCLI_MOCK_SERVER, or none.

      -s, --server URL                Use the WBEM server at the specified URL with format: [SCHEME://]HOST[:PORT]. SCHEME
                                      must be "https" (default) or "http". HOST is a short or long hostname or literal
                                      IPV4/v6 address. PORT defaults to 5989 for https and 5988 for http. This option is
                                      mutually exclusive with the --mock-server and --name options, since each defines a
                                      WBEM server. Default: EnvVar PYWBEMCLI_SERVER, or none.

      -u, --user TEXT                 User name for the WBEM server.  Use "" to set default in interactive mode.Default:
                                      EnvVar PYWBEMCLI_USER, or none.

      -p, --password TEXT             Password for the WBEM server. Default: EnvVar PYWBEMCLI_PASSWORD, or prompted for if
                                      --user specified. Use "" to set default in interactive mode.

      --verify / --no-verify          If --verify, client verifies the X.509 server certificate presented by the WBEM server
                                      during TLS/SSL handshake. If --no-verify client bypasses verification. Default: EnvVar
                                      PYWBEMCLI_VERIFY, or "--verify".

      --ca-certs CACERTS              Certificates used to validate the certificate presented by the WBEM server during
                                      TLS/SSL handshake: FILE: Use the certs in the specified PEM file; DIR: Use the certs
                                      in the PEM files in the specified directory; "certifi" (pywbem 1.0 or later): Use the
                                      certs provided by the certifi Python package; Default: EnvVar PYWBEMCLI_CA_CERTS, or
                                      "certifi" (pywbem 1.0 or later), or the certs in the PEM files in the first existing
                                      directory from from a system defined list of directories (pywbem before 1.0).

      -c, --certfile FILE             Path name of a PEM file containing a X.509 client certificate that is used to enable
                                      TLS/SSL 2-way authentication by presenting the certificate to the WBEM server during
                                      TLS/SSL handshake.  Use "" to set default in interactive mode. Default: EnvVar
                                      PYWBEMCLI_CERTFILE, or none.

      -k, --keyfile FILE              Path name of a PEM file containing a X.509 private key that belongs to the certificate
                                      in the --certfile file. Not required if the private key is part of the --certfile
                                      file. Use "" to set default in interactive mode.Default: EnvVar PYWBEMCLI_KEYFILE, or
                                      none.

      -t, --timeout INT               Client-side timeout in seconds for operations with the WBEM server. Default: EnvVar
                                      PYWBEMCLI_TIMEOUT, or 30.

      -U, --use-pull [yes|no|either]  Determines whether pull operations are used for operations with the WBEM server that
                                      return lists of instances, as follows: "yes" uses pull operations and fails if not
                                      supported by the server; "no" uses traditional operations; "either" (default) uses
                                      pull operations if supported by the server, and otherwise traditional operations.
                                      Default: EnvVar PYWBEMCLI_USE_PULL, or "either".

      --pull-max-cnt INT              Maximum number of instances to be returned by the WBEM server in each open or pull
                                      response, if pull operations are used. This is a tuning parameter that does not affect
                                      the external behavior of the commands. Default: EnvVar PYWBEMCLI_PULL_MAX_CNT, or 1000

      -T, --timestats / --no-timestats
                                      Display operation time statistics gathered by pywbemcli after each command. Otherwise
                                      statistics can be displayed with "statistics show" command. Default: EnvVar
                                      PYWBEMCLI_TIMESTATS, or no-timestats.

      -d, --default-namespace NAMESPACE
                                      Default namespace, to be used when commands do not specify the --namespace command
                                      option. Use "" to set default in interactive mode. Default: EnvVar
                                      PYWBEMCLI_DEFAULT_NAMESPACE, or root/cimv2.

      -o, --output-format FORMAT      Output format for the command result. The default and allowed output formats are
                                      command specific. The default output_format is None so that each command selects its
                                      own default format. Use "" to set default in interactive mode. FORMAT is: table
                                      formats: [table|plain|simple|grid|psql|rst|html]; CIM object formats:
                                      [mof|xml|repr|txt]]; TEXT formats: [text].

      -l, --log COMP[=DEST[:DETAIL]],...
                                      Enable logging of the WBEM operations, defined by a list of log configuration strings
                                      with: COMP: [api|http|all]; DEST: [file|stderr|off], default: file; DETAIL:
                                      [all|paths|summary], default: all.  Use "" to set default in interactive modeDefault:
                                      EnvVar PYWBEMCLI_LOG, or all.

      -v, --verbose / --no-verbose    Display extra information about the processing.
      --warn / --no-warn              Warnings control: True enables display of all Python warnings; False leaves warning
                                      control to the PYHONWARNINGS env var, which by default displays no warnings. Default:
                                      False.

      -C, --connections-file FILE PATH
                                      Path name of the connections file to be used. Default: EnvVar
                                      PYWBEMCLI_CONNECTIONS_FILE, or ".pywbemcli_connections.yaml" in the user's home
                                      directory (as determined using Python's os.path.expanduser("~"). See there for
                                      details, particularly for Windows). Use "" to set default in interactive mode.

      --pdb                           Pause execution in the built-in pdb debugger just before executing the command within
                                      pywbemcli. Ignored in interactive mode, but can be specified on each interactive
                                      command. Default: EnvVar PYWBEMCLI_PDB, or false.

      --version                       Show the version of this command and the pywbem package.
      -h, --help                      Show this help message.

    Commands:
      class         Command group for CIM classes.
      instance      Command group for CIM instances.
      namespace     Command group for CIM namespaces.
      profile       Command group for WBEM management profiles.
      qualifier     Command group for CIM qualifier declarations.
      server        Command group for WBEM servers.
      statistics    Command group for WBEM operation statistics.
      subscription  Command group to manage WBEM subscriptions.
      connection    Command group for WBEM connection definitions.
      help          Show help message for interactive mode.
      repl          Enter interactive mode (default).


.. _`pywbemcli class --help`:

pywbemcli class --help
----------------------



Help text for ``pywbemcli class`` (see :ref:`class command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for CIM classes.

      This command group defines commands to inspect classes, invoke methods on classes, delete classes.

      Creation and modification of classes is not currently supported.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'class' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      enumerate     List top classes or subclasses of a class in a namespace.
      get           Get a class.
      delete        Delete a class.
      invokemethod  Invoke a method on a class.
      references    List the classes referencing a class.
      associators   List the classes associated with a class.
      find          List the classes with matching class names on the server.
      tree          Show the subclass or superclass hierarchy for a class.


.. _`pywbemcli class associators --help`:

pywbemcli class associators --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class associators`` (see :ref:`class associators command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class associators CLASSNAME [COMMAND-OPTIONS]

      List the classes associated with a class.

      List the CIM classes that are associated with the specified class (CLASSNAME argument) in the specified CIM
      namespace (--namespace option). If no namespace was specified, the default namespace of the connection is used.

      The classes to be retrieved can be filtered by the --role, --result-role, --assoc-class, and --result-class options.

      The --include-classorigin, --no-qualifiers, and --propertylist options determine which parts are included in each
      retrieved class.

      The --names-only option can be used to show only the class paths.

      In the output, the classes and class paths will be formatted as defined by the --output-format general option. Table
      formats on classes will be replaced with MOF format.

      Examples:

        pywbemcli -n myconn class associators CIM_Foo -n interop

    Command Options:
      --ac, --assoc-class CLASSNAME   Filter the result set by association class name. Subclasses of the specified class
                                      also match.

      --rc, --result-class CLASSNAME  Filter the result set by result class name. Subclasses of the specified class also
                                      match.

      -r, --role PROPERTYNAME         Filter the result set by source end role name.
      --rr, --result-role PROPERTYNAME
                                      Filter the result set by far end role name.
      --nq, --no-qualifiers           Do not include qualifiers in the returned class(es). Default: Include qualifiers.
      --ico, --include-classorigin    Include class origin information in the returned class(es). Default: Do not include
                                      class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      -h, --help                      Show this help message.


.. _`pywbemcli class delete --help`:

pywbemcli class delete --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class delete`` (see :ref:`class delete command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class delete CLASSNAME [COMMAND-OPTIONS]

      Delete a class.

      Delete a CIM class (CLASSNAME argument) in a CIM namespace (--namespace option). If no namespace was specified, the
      default namespace of the connection is used.

      If the class has instances, the command is rejected, unless the --include-instances option is specified, in which
      case the instances are also deleted.

      If other classes in that namespace depend on the class to be deleted, the command is rejected. Dependencies
      considered for this purpose are subclasses, referencing classes and embedding classes (EmbeddedInstance qualifier
      only).

      WARNING: Deletion of instances will cause the removal of corresponding resources in the managed environment (i.e. in
      the real world). Some instances may not be deletable.

      WARNING: Deleting classes can cause damage to the server: It can impact instance providers and other components in
      the server. Use this command with caution.

      Many WBEM servers may not allow this operation or may severely limit the conditions under which a class can be
      deleted from the server.

      Example:

        pywbemcli -n myconn class delete CIM_Foo -n interop

    Command Options:
      -f, --force                Same as --include-instances. The -f / --force option has been deprecated and will be
                                 removed in a future version.

      --include-instances        Delete any instances of the class as well. WARNING: Deletion of instances will cause the
                                 removal of corresponding resources in the managed environment (i.e. in the real
                                 world).Default: Reject command if the class has any instances.

      --dry-run                  Enable dry-run mode: Do not actually delete the objects, but display what would be done.
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                 Show this help message.


.. _`pywbemcli class enumerate --help`:

pywbemcli class enumerate --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class enumerate`` (see :ref:`class enumerate command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class enumerate CLASSNAME [COMMAND-OPTIONS]

      List top classes or subclasses of a class in a namespace.

      Enumerate CIM classes starting either at the top of the class hierarchy in the specified CIM namespace (--namespace
      option), or at the specified class (CLASSNAME argument) in the specified namespace. If no namespace was specified,
      the default namespace of the connection is used.

      The --local-only, --include-classorigin, and --no-qualifiers options determine which parts are included in each
      retrieved class.

      The --deep-inheritance option defines whether or not the complete subclass hierarchy of the classes is retrieved.

      The --names-only option can be used to show only the class paths.

      In the output, the classes and class paths will be formatted as defined by the --output-format general option. Table
      formats on classes will be replaced with MOF format.

      Examples:

        pywbemcli -n myconn class enumerate -n interop

        pywbemcli -n myconn class enumerate CIM_Foo -n interop

    Command Options:
      --di, --deep-inheritance        Include the complete subclass hierarchy of the requested classes in the result set.
                                      Default: Do not include subclasses.

      --lo, --local-only              Do not include superclass properties and methods in the returned class(es). Default:
                                      Include superclass properties and methods.

      --nq, --no-qualifiers           Do not include qualifiers in the returned class(es). Default: Include qualifiers.
      --ico, --include-classorigin    Include class origin information in the returned class(es). Default: Do not include
                                      class origin information.

      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      --association / --no-association
                                      Filter the returned classes to return only indication classes (--association) or
                                      classes that are not associations(--no-association). If the option is not defined no
                                      filtering occurs

      --indication / --no-indication  Filter the returned classes to return only indication classes (--indication) or
                                      classes that are not indications (--no-indication). If the option is not defined no
                                      filtering occurs

      --experimental / --no-experimental
                                      Filter the returned classes to return only experimental classes (--experimental) or
                                      classes that are not experimental (--no-iexperimental). If the option is not defined
                                      no filtering occurs

      --deprecated / --no-deprecated  Filter the returned classes to return only deprecated classes (--deprecated) or
                                      classes that are not deprecated (--no-deprecated). If the option is not defined no
                                      filtering occurs

      --since VERSION                 Filter the returned classes to return only classes  with a version qualifier ge the
                                      supplied string. The string must define a version of the form M.N.V consistent the
                                      definitions of the VERSION qualifier.

      --schema SCHEMA                 Filter the returned classes to return only classes where the classname scheme
                                      component (characters before the "_" match the scheme provided.

      --subclass-of CLASSNAME         Filter the returned classes to return only classes that are a subclass of the option
                                      value.

      --leaf-classes                  Filter the returned classes to return only leaf (classes; classes with no subclass.
      -h, --help                      Show this help message.


.. _`pywbemcli class find --help`:

pywbemcli class find --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class find`` (see :ref:`class find command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class find CLASSNAME-GLOB [COMMAND-OPTIONS]

      List the classes with matching class names on the server.

      Find the CIM classes whose class name matches the specified wildcard expression (CLASSNAME-GLOB argument) in all CIM
      namespaces of the WBEM server, or in the specified namespace (--namespace option).

      The CLASSNAME-GLOB argument is a wildcard expression that is matched on class names case insensitively. The special
      characters from Unix file name wildcarding are supported ('*' to match zero or more characters, '?' to match a
      single character, and '[]' to match character ranges). To avoid shell expansion of wildcard characters, the
      CLASSNAME-GLOB argument should be put in quotes.

      For example, "pywbem_*" returns classes whose name begins with "PyWBEM_", "pywbem_", etc. "*system*" returns classes
      whose names include the case insensitive string "system".

      In the output, the classes will be formatted as defined by the --output-format general option if it specifies table
      output. Otherwise the classes will be in the form "NAMESPACE:CLASSNAME".

      Examples:

        pywbemcli -n myconn class find "CIM_*System*" -n interop

        pywbemcli -n myconn class find *Foo*

    Command Options:
      -n, --namespace NAMESPACE       Add a namespace to the search scope. May be specified multiple times. Default: Search
                                      in all namespaces of the server.

      -s, --sort                      Sort by namespace. Default is to sort by classname
      --association / --no-association
                                      Filter the returned classes to return only indication classes (--association) or
                                      classes that are not associations(--no-association). If the option is not defined no
                                      filtering occurs

      --indication / --no-indication  Filter the returned classes to return only indication classes (--indication) or
                                      classes that are not indications (--no-indication). If the option is not defined no
                                      filtering occurs

      --experimental / --no-experimental
                                      Filter the returned classes to return only experimental classes (--experimental) or
                                      classes that are not experimental (--no-iexperimental). If the option is not defined
                                      no filtering occurs

      --deprecated / --no-deprecated  Filter the returned classes to return only deprecated classes (--deprecated) or
                                      classes that are not deprecated (--no-deprecated). If the option is not defined no
                                      filtering occurs

      --since VERSION                 Filter the returned classes to return only classes  with a version qualifier ge the
                                      supplied string. The string must define a version of the form M.N.V consistent the
                                      definitions of the VERSION qualifier.

      --schema SCHEMA                 Filter the returned classes to return only classes where the classname scheme
                                      component (characters before the "_" match the scheme provided.

      --subclass-of CLASSNAME         Filter the returned classes to return only classes that are a subclass of the option
                                      value.

      --leaf-classes                  Filter the returned classes to return only leaf (classes; classes with no subclass.
      -h, --help                      Show this help message.


.. _`pywbemcli class get --help`:

pywbemcli class get --help
^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class get`` (see :ref:`class get command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class get CLASSNAME [COMMAND-OPTIONS]

      Get a class.

      Get a CIM class (CLASSNAME argument) in a CIM namespace (--namespace option). If no namespace was specified, the
      default namespace of the connection is used.

      The --local-only, --include-classorigin, --no-qualifiers, and --propertylist options determine which parts are
      included in each retrieved class.

      In the output, the class will be formatted as defined by the --output-format general option. Table formats are
      replaced with MOF format.

      Example:

        pywbemcli -n myconn class get CIM_Foo -n interop

    Command Options:
      --lo, --local-only              Do not include superclass properties and methods in the returned class(es). Default:
                                      Include superclass properties and methods.

      --nq, --no-qualifiers           Do not include qualifiers in the returned class(es). Default: Include qualifiers.
      --ico, --include-classorigin    Include class origin information in the returned class(es). Default: Do not include
                                      class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                      Show this help message.


.. _`pywbemcli class invokemethod --help`:

pywbemcli class invokemethod --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class invokemethod`` (see :ref:`class invokemethod command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class invokemethod CLASSNAME METHODNAME [COMMAND-OPTIONS]

      Invoke a method on a class.

      Invoke a static CIM method (METHODNAME argument) on a CIM class (CLASSNAME argument) in a CIM namespace (--namespace
      option), and display the method return value and output parameters. If no namespace was specified, the default
      namespace of the connection is used.

      The method input parameters are specified using the --parameter option, which may be specified multiple times.

      Pywbemcli retrieves the class definition from the server in order to verify that the specified input parameters are
      consistent with the parameter characteristics in the method definition.

      Use the 'instance invokemethod' command to invoke CIM methods on CIM instances.

      Example:

        pywbemcli -n myconn class invokemethod CIM_Foo methodx -p p1=9 -p p2=Fred

    Command Options:
      -p, --parameter PARAMETERNAME=VALUE
                                      Specify a method input parameter with its value. May be specified multiple times.
                                      Default: No input parameters.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                      Show this help message.


.. _`pywbemcli class references --help`:

pywbemcli class references --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class references`` (see :ref:`class references command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class references CLASSNAME [COMMAND-OPTIONS]

      List the classes referencing a class.

      List the CIM (association) classes that reference the specified class (CLASSNAME argument) in the specified CIM
      namespace (--namespace option). If no namespace was specified, the default namespace of the connection is used.

      The classes to be retrieved can be filtered by the --role and --result-class options.

      The --include-classorigin, --no-qualifiers, and --propertylist options determine which parts are included in each
      retrieved class.

      The --names-only option can be used to show only the class paths.

      In the output, the classes and class paths will be formatted as defined by the --output-format general option. Table
      formats on classes will be replaced with MOF format.

      Examples:

        pywbemcli -n myconn class references CIM_Foo -n interop

    Command Options:
      --rc, --result-class CLASSNAME  Filter the result set by result class name. Subclasses of the specified class also
                                      match.

      -r, --role PROPERTYNAME         Filter the result set by source end role name.
      --nq, --no-qualifiers           Do not include qualifiers in the returned class(es). Default: Include qualifiers.
      --ico, --include-classorigin    Include class origin information in the returned class(es). Default: Do not include
                                      class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      -h, --help                      Show this help message.


.. _`pywbemcli class tree --help`:

pywbemcli class tree --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli class tree`` (see :ref:`class tree command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] class tree CLASSNAME [COMMAND-OPTIONS]

      Show the subclass or superclass hierarchy for a class.

      List the subclass or superclass hierarchy of a CIM class (CLASSNAME argument) or CIM namespace (--namespace option):

      - If CLASSNAME is omitted, the complete class hierarchy of the specified   namespace is retrieved.

      - If CLASSNAME is specified but not --superclasses, the class and its   subclass hierarchy in the specified
      namespace are retrieved.

      - If CLASSNAME and --superclasses are specified, the class and its   superclass ancestry up to the top-level class
      in the specified namespace   are retrieved.

      If no namespace was specified, the default namespace of the connection is used.

      The class hierarchy will formatted as a ASCII graphical tree; the --output-format general option is ignored.

      The --detail options to display extra information about each class including:

      -  The Version qualifier value if the class includes a version    qualifier. This is normally a string with 3
      integers

      -  Information about each class type (Association, Indication, Abstract)

      Examples:

        # Display the complete class hierarchy from the interop namespace   pywbemcli -n myconn class tree -n interop

        # Display CIM_Foo an its subclasses from the namespace interop   pywbemcli -n myconn class tree CIM_Foo -n interop

        # Display CIM_Foo and its superclasses from interop   pywbemcli -n myconn class tree CIM_Foo -s -n interop

    Command Options:
      -s, --superclasses         Show the superclass hierarchy. Default: Show the subclass hierarchy.
      -d, --detail               Show details about the class: the Version,  Association, Indication, and Abstact
                                 qualifiers.

      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                 Show this help message.


.. _`pywbemcli connection --help`:

pywbemcli connection --help
---------------------------



Help text for ``pywbemcli connection`` (see :ref:`connection command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for WBEM connection definitions.

      This command group defines commands to manage persistent WBEM connection definitions that have a name. The names of
      these connection definitions can then be used as shorthand for the WBEM server or mock server via the '--name'
      general option.

      The connection definitions are stored in a connections file. By default, the connections file is
      '.pywbemcli_connections.yaml' in the user's home directory. The location of the user's home directory depends on the
      operating system used. It is determined with Python's 'os.path.expanduser("~")', which works on all operating
      systems including Windows. The default path name of the connections file can be overwritten using the
      'PYWBEMCLI_CONNECTIONS_FILE' environment variable, or with the '--connections-file' general option.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'connection' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      export  Export the current connection.
      show    Show a WBEM connection definition or the current connection.
      delete  Delete a WBEM connection definition.
      select  Select a WBEM connection definition as current or default.
      test    Test the current connection with a predefined WBEM request.
      save    Save the current connection to a new WBEM connection definition.
      list    List the WBEM connection definitions.


.. _`pywbemcli connection delete --help`:

pywbemcli connection delete --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection delete`` (see :ref:`connection delete command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection delete NAME [COMMAND-OPTIONS]

      Delete a WBEM connection definition.

      Delete a named connection definition from the connections file. If the NAME argument is omitted, prompt for
      selecting one of the connection definitions in the connections file.

      Example:

        pywbemcli connection delete blah

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli connection export --help`:

pywbemcli connection export --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection export`` (see :ref:`connection export command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection export [COMMAND-OPTIONS]

      Export the current connection.

      Display commands that set pywbemcli environment variables to the parameters of the current connection.

      Examples:

        pywbemcli --name srv1 connection export

        pywbemcli --server https://srv1 --user me --password pw connection export

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli connection list --help`:

pywbemcli connection list --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection list`` (see :ref:`connection list command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection list [COMMAND-OPTIONS]

      List the WBEM connection definitions.

      This command displays all entries in the connections file and the current connection if it exists and is not in the
      connections file as a table.

      '#' before the name indicates the default connection.
      '*' before the name indicates that it is the current connection.

      See also the 'connection select' command.

    Command Options:
      -f, --full  If set, display the full table. Otherwise display a brief view(name, server, mock_server columns).
      -h, --help  Show this help message.


.. _`pywbemcli connection save --help`:

pywbemcli connection save --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection save`` (see :ref:`connection save command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection save NAME [COMMAND-OPTIONS]

      Save the current connection to a new WBEM connection definition.

      Save the current connection to the connections file as a connection definition named NAME. The NAME argument is
      required. If a connection definition with that name already exists, it is overwritten without warning.

      In the interactive mode, general options that are connection related are applied to the current connection before it
      is saved.

      Examples:

        pywbemcli --server https://srv1 connection save mysrv

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli connection select --help`:

pywbemcli connection select --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection select`` (see :ref:`connection select command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection select NAME [COMMAND-OPTIONS]

      Select a WBEM connection definition as current or default.

      Select the connection definition named NAME from the connections file to be the current connection. The connection
      definition in the connections file must exist. If the NAME argument is omitted, a list of connection definitions
      from the connections file is presented with a prompt for the user to select a connection definition.

      If the --default option is set, the default connection is set to the selected connection definition, in addition.
      Once defined, the default connection will be used as a default in future executions of pywbemcli if none of the
      server-defining general options (i.e. --server, --mock-server, or --name) was used.

      The 'connection list' command marks the current connection with '*' and the default connection with '#'.

      Example of selecting a default connection in command mode:

        pywbemcli connection select myconn --default
        pywbemcli connection show
        name: myconn
          . . .

      Example of selecting just the current connection in interactive mode:

        pywbemcli
        pywbemcli> connection select myconn
        pywbemcli> connection show
        name: myconn
          . . .

    Command Options:
      -d, --default  If set, the connection is set to be the default connection in the connections file in addition to
                     setting it as the current connection.

      -h, --help     Show this help message.


.. _`pywbemcli connection show --help`:

pywbemcli connection show --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection show`` (see :ref:`connection show command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection show NAME [COMMAND-OPTIONS]

      Show a WBEM connection definition or the current connection.

      Show the name and attributes of a WBEM connection definition or the current connection, as follows:

      * If the NAME argument is specified, display the connection information   with that name from the connections file
      or the current connection if it   is the same name.

      * If the NAME argument is '?', the command presents a list of connection   definitions from the connections file and
      prompts the user to   select one, which is then displayed.

      * If the NAME argument is omitted, displays the current connection   information if there is a current connection.

      Example showing a named connection definition:

        pywbemcli connection show svr1
          name: svr1
          ...

      Example for prompting for a connection definition:

        pywbemcli connection show ?
          0: svr1
          1: svr2
        Input integer between 0 and 2 or Ctrl-C to exit selection: : 0
          name: svr1
            ...

    Command Options:
      --show-password  If set, show existing password in results. Otherwise, password is masked
      -h, --help       Show this help message.


.. _`pywbemcli connection test --help`:

pywbemcli connection test --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli connection test`` (see :ref:`connection test command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] connection test [COMMAND-OPTIONS]

      Test the current connection with a predefined WBEM request.

      Execute the EnumerateClassNames operation on the default namespace against the current connection to confirm that
      the connection exists and is working.

      Examples:

        pywbemcli --name mysrv connection test

    Command Options:
      --test-pull  If set, the connection is tested to determine if theDMTF defined pull operations (ex.
                   OpenEnumerateInstancesare implemented since these are optional.

      -h, --help   Show this help message.


.. _`pywbemcli help --help`:

pywbemcli help --help
---------------------



Help text for ``pywbemcli help`` (see :ref:`help command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] help

      Show help message for interactive mode.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli instance --help`:

pywbemcli instance --help
-------------------------



Help text for ``pywbemcli instance`` (see :ref:`instance command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for CIM instances.

      This command group defines commands to inspect instances, to invoke methods on instances, and to create and delete
      instances.

      Modification of instances is not currently supported.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'instance' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      enumerate     List the instances of a class.
      get           Get an instance of a class.
      delete        Delete an instance of a class.
      create        Create an instance of a class in a namespace.
      modify        Modify properties of an instance.
      associators   List the instances associated with an instance.
      references    List the instances referencing an instance.
      invokemethod  Invoke a method on an instance.
      query         Execute a query on instances in a namespace.
      count         Count the instances of each class with matching class name.
      shrub         Show the association shrub for INSTANCENAME.


.. _`pywbemcli instance associators --help`:

pywbemcli instance associators --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance associators`` (see :ref:`instance associators command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance associators INSTANCENAME [COMMAND-OPTIONS]

      List the instances associated with an instance.

      List the CIM instances that are associated with the specified CIM instance, and display the returned instances, or
      instance paths if --names-only was specified.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      The instances to be retrieved can be filtered by the --filter-query, --role, --result-role, --assoc-class, and
      --result-class options.

      The --include-qualifiers, --include-classorigin, and --propertylist options determine which parts are included in
      each retrieved instance.

      The --names-only option can be used to show only the instance paths.

      In the output, the instances and instance paths will be formatted as defined by the --output-format general option.
      Table formats on instances will be replaced with MOF format.

    Command Options:
      --ac, --assoc-class CLASSNAME   Filter the result set by association class name. Subclasses of the specified class
                                      also match.

      --rc, --result-class CLASSNAME  Filter the result set by result class name. Subclasses of the specified class also
                                      match.

      -r, --role PROPERTYNAME         Filter the result set by source end role name.
      --rr, --result-role PROPERTYNAME
                                      Filter the result set by far end role name.
      --iq, --include-qualifiers      When traditional operations are used, include qualifiers in the returned instances.
                                      Some servers may ignore this option. By default, and when pull operations are used,
                                      qualifiers will never be included.

      --ico, --include-classorigin    Include class origin information in the returned instance(s). Some servers may ignore
                                      this option. Default: Do not include class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      --fq, --filter-query QUERY-STRING
                                      When pull operations are used, filter the instances in the result via a filter query.
                                      By default, and when traditional operations are used, no such filtering takes place.

      --fql, --filter-query-language QUERY-LANGUAGE
                                      The filter query language to be used with --filter-query. Default: DMTF:FQL.
      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli instance count --help`:

pywbemcli instance count --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance count`` (see :ref:`instance count command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance count CLASSNAME-GLOB [COMMAND-OPTIONS]

      Count the instances of each class with matching class name.

      Display the count of instances of each CIM class whose class name matches the specified wildcard expression
      (CLASSNAME-GLOB) in all CIM namespaces of the WBEM server, or in the specified namespaces (--namespace option).
      This differs from instance enumerate, etc. in that it counts the instances specifically for the classname of each
      instance returned, not including subclasses.

      The CLASSNAME-GLOB argument is a wildcard expression that is matched on class names case insensitively. The special
      characters from Unix file name wildcarding are supported ('*' to match zero or more characters, '?' to match a
      single character, and '[]' to match character ranges). To avoid shell expansion of wildcard characters, the
      CLASSNAME-GLOB argument should be put in quotes.

      If CLASSNAME-GLOB is not specified, then all classes in the specified namespaces are counted (same as when
      specifying CLASSNAME-GLOB as "*").

      For example, "pywbem_*" returns classes whose name begins with "PyWBEM_", "pywbem_", etc. "*system*" returns classes
      whose names include the case insensitive string "system".

      This command can take a long time to execute since it potentially enumerates all instance names for all classes in
      all namespaces.

    Command Options:
      -n, --namespace NAMESPACE       Add a namespace to the search scope. May be specified multiple times. Default: Search
                                      in all namespaces of the server.

      -s, --sort                      Sort by instance count. Otherwise sorted by class name.
      --association / --no-association
                                      Filter the returned classes to return only indication classes (--association) or
                                      classes that are not associations(--no-association). If the option is not defined no
                                      filtering occurs

      --indication / --no-indication  Filter the returned classes to return only indication classes (--indication) or
                                      classes that are not indications (--no-indication). If the option is not defined no
                                      filtering occurs

      --experimental / --no-experimental
                                      Filter the returned classes to return only experimental classes (--experimental) or
                                      classes that are not experimental (--no-iexperimental). If the option is not defined
                                      no filtering occurs

      --deprecated / --no-deprecated  Filter the returned classes to return only deprecated classes (--deprecated) or
                                      classes that are not deprecated (--no-deprecated). If the option is not defined no
                                      filtering occurs

      --since VERSION                 Filter the returned classes to return only classes  with a version qualifier ge the
                                      supplied string. The string must define a version of the form M.N.V consistent the
                                      definitions of the VERSION qualifier.

      --schema SCHEMA                 Filter the returned classes to return only classes where the classname scheme
                                      component (characters before the "_" match the scheme provided.

      --subclass-of CLASSNAME         Filter the returned classes to return only classes that are a subclass of the option
                                      value.

      --leaf-classes                  Filter the returned classes to return only leaf (classes; classes with no subclass.
      -h, --help                      Show this help message.


.. _`pywbemcli instance create --help`:

pywbemcli instance create --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance create`` (see :ref:`instance create command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance create CLASSNAME [COMMAND-OPTIONS]

      Create an instance of a class in a namespace.

      Create a CIM instance of the specified creation class (CLASSNAME argument) in the specified CIM namespace
      (--namespace option), with the specified properties (--property options) and display the CIM instance path of the
      created instance. If no namespace was specified, the default namespace of the connection is used.

      The properties to be initialized and their new values are specified using the --property option, which may be
      specified multiple times.

      Pywbemcli retrieves the class definition from the server in order to verify that the specified properties are
      consistent with the property characteristics in the class definition.

      Example:

        pywbemcli instance create CIM_blah -P id=3 -P arr="bla bla",foo

    Command Options:
      -p, --property PROPERTYNAME=VALUE
                                      Initial property value for the new instance. May be specified multiple times. Array
                                      property values are specified as a comma-separated list; embedded instances are not
                                      supported. Default: No initial properties provided.

      -V, --verify                    Prompt for confirmation before performing a change, to allow for verification of
                                      parameters. Default: Do not prompt for confirmation.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                      Show this help message.


.. _`pywbemcli instance delete --help`:

pywbemcli instance delete --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance delete`` (see :ref:`instance delete command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance delete INSTANCENAME [COMMAND-OPTIONS]

      Delete an instance of a class.

      WARNING: Deletion of instances will cause the removal of corresponding resources in the managed environment (i.e. in
      the real world). Some instances may not be deletable.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

    Command Options:
      -k, --key KEYNAME=VALUE    Value for a key in keybinding of CIM instance name. May be specified multiple times. Allows
                                 defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      --hi, --help-instancename  Show help message for specifying INSTANCENAME including use of the --key and --namespace
                                 options.

      -h, --help                 Show this help message.


.. _`pywbemcli instance enumerate --help`:

pywbemcli instance enumerate --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance enumerate`` (see :ref:`instance enumerate command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance enumerate CLASSNAME [COMMAND-OPTIONS]

      List the instances of a class.

      Enumerate the CIM instances of the specified class (CLASSNAME argument), including instances of subclasses in the
      specified CIM namespace (--namespace option), and display the returned instances, or instance paths if --names-only
      was specified. If no namespace was specified, the default namespace of the connection is used.

      The instances to be retrieved can be filtered by the --filter-query option.

      The --local-only, --deep-inheritance, --include-qualifiers, --include-classorigin, and --propertylist options
      determine which parts are included in each retrieved instance.

      The --names-only option can be used to show only the instance paths.

      In the output, the instances and instance paths will be formatted as defined by the --output-format general option.
      Table formats on instances will be replaced with MOF format.

    Command Options:
      --lo, --local-only              When traditional operations are used, do not include superclass properties in the
                                      returned instances. Some servers may ignore this option. By default, and when pull
                                      operations are used, superclass properties will always be included.

      --di, --deep-inheritance        Include subclass properties in the returned instances. Default: Do not include
                                      subclass properties.

      --iq, --include-qualifiers      When traditional operations are used, include qualifiers in the returned instances.
                                      Some servers may ignore this option. By default, and when pull operations are used,
                                      qualifiers will never be included.

      --ico, --include-classorigin    Include class origin information in the returned instance(s). Some servers may ignore
                                      this option. Default: Do not include class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -s, --summary                   Show only a summary (count) of the objects.
      --fq, --filter-query QUERY-STRING
                                      When pull operations are used, filter the instances in the result via a filter query.
                                      By default, and when traditional operations are used, no such filtering takes place.

      --fql, --filter-query-language QUERY-LANGUAGE
                                      The filter query language to be used with --filter-query. Default: DMTF:FQL.
      -h, --help                      Show this help message.


.. _`pywbemcli instance get --help`:

pywbemcli instance get --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance get`` (see :ref:`instance get command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance get INSTANCENAME [COMMAND-OPTIONS]

      Get an instance of a class.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      The --local-only, --include-qualifiers, --include-classorigin, and --propertylist options determine which parts are
      included in the retrieved instance.

      In the output, the instance will formatted as defined by the --output-format general option.

    Command Options:
      --lo, --local-only              Do not include superclass properties in the returned instance. Some servers may ignore
                                      this option. Default: Include superclass properties.

      --iq, --include-qualifiers      Include qualifiers in the returned instance. Not all servers return qualifiers on
                                      instances. Default: Do not include qualifiers.

      --ico, --include-classorigin    Include class origin information in the returned instance(s). Some servers may ignore
                                      this option. Default: Do not include class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli instance invokemethod --help`:

pywbemcli instance invokemethod --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance invokemethod`` (see :ref:`instance invokemethod command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance invokemethod INSTANCENAME METHODNAME [COMMAND-OPTIONS]

      Invoke a method on an instance.

      Invoke a CIM method (METHODNAME argument) on a CIM instance with the specified input parameters (--parameter
      options), and display the method return value and output parameters.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      The method input parameters are specified using the --parameter option, which may be specified multiple times.

      Pywbemcli retrieves the class definition of the creation class of the instance from the server in order to verify
      that the specified input parameters are consistent with the parameter characteristics in the method definition.

      Use the 'class invokemethod' command to invoke CIM methods on CIM classes.

      Example:

        pywbemcli -n myconn instance invokemethod CIM_x.id='hi" methodx -p id=3

    Command Options:
      -p, --parameter PARAMETERNAME=VALUE
                                      Specify a method input parameter with its value. May be specified multiple times.
                                      Array property values are specified as a comma-separated list; embedded instances are
                                      not supported. Default: No input parameters.

      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli instance modify --help`:

pywbemcli instance modify --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance modify`` (see :ref:`instance modify command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance modify INSTANCENAME [COMMAND-OPTIONS]

      Modify properties of an instance.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      The properties to be modified and their new values are specified using the --property option, which may be specified
      multiple times.

      The --propertylist option allows restricting the set of properties to be modified. Given that the set of properties
      to be modified is already determined by the specified --property options, it does not need to be specified.

      Example:

        pywbemcli instance modify CIM_blah.fred=3 -P id=3 -P arr="bla bla",foo

    Command Options:
      -p, --property PROPERTYNAME=VALUE
                                      Property to be modified, with its new value. May be specified once for each property
                                      to be modified. Array property values are specified as a comma-separated list;
                                      embedded instances are not supported. Default: No properties modified.

      --pl, --propertylist PROPERTYLIST
                                      Reduce the properties to be modified (as per --property) to a specific property list.
                                      Multiple properties may be specified with either a comma-separated list or by using
                                      the option multiple times. The empty string will cause no properties to be modified.
                                      Default: Do not reduce the properties to be modified.

      -V, --verify                    Prompt for confirmation before performing a change, to allow for verification of
                                      parameters. Default: Do not prompt for confirmation.

      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli instance query --help`:

pywbemcli instance query --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance query`` (see :ref:`instance query command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance query QUERY-STRING [COMMAND-OPTIONS]

      Execute a query on instances in a namespace.

      Execute the specified query (QUERY_STRING argument) in the specified CIM namespace (--namespace option), and display
      the returned instances. If no namespace was specified, the default namespace of the connection is used.

      In the output, the instances will formatted as defined by the --output-format general option.

    Command Options:
      --ql, --query-language QUERY-LANGUAGE
                                      The query language to be used with --query. Default: DMTF:CQL.
      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      -h, --help                      Show this help message.


.. _`pywbemcli instance references --help`:

pywbemcli instance references --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance references`` (see :ref:`instance references command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance references INSTANCENAME [COMMAND-OPTIONS]

      List the instances referencing an instance.

      List the CIM (association) instances that reference the specified CIM instance, and display the returned instances,
      or instance paths if --names-only was specified.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      The instances to be retrieved can be filtered by the --filter-query, --role and --result-class options.

      The --include-qualifiers, --include-classorigin, and --propertylist options determine which parts are included in
      each retrieved instance.

      The --names-only option can be used to show only the instance paths.

      In the output, the instances and instance paths will be formatted as defined by the --output-format general option.
      Table formats on instances will be replaced with MOF format.

    Command Options:
      --rc, --result-class CLASSNAME  Filter the result set by result class name. Subclasses of the specified class also
                                      match.

      -r, --role PROPERTYNAME         Filter the result set by source end role name.
      --iq, --include-qualifiers      When traditional operations are used, include qualifiers in the returned instances.
                                      Some servers may ignore this option. By default, and when pull operations are used,
                                      qualifiers will never be included.

      --ico, --include-classorigin    Include class origin information in the returned instance(s). Some servers may ignore
                                      this option. Default: Do not include class origin information.

      --pl, --propertylist PROPERTYLIST
                                      Filter the properties included in the returned object(s). Multiple properties may be
                                      specified with either a comma-separated list or by using the option multiple times.
                                      Properties specified in this option that are not in the object(s) will be ignored. The
                                      empty string will include no properties. Default: Do not filter properties.

      --no, --names-only              Retrieve only the object paths (names). Default: Retrieve the complete objects
                                      including object paths.

      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      --fq, --filter-query QUERY-STRING
                                      When pull operations are used, filter the instances in the result via a filter query.
                                      By default, and when traditional operations are used, no such filtering takes place.

      --fql, --filter-query-language QUERY-LANGUAGE
                                      The filter query language to be used with --filter-query. Default: DMTF:FQL.
      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli instance shrub --help`:

pywbemcli instance shrub --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli instance shrub`` (see :ref:`instance shrub command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] instance shrub INSTANCENAME [COMMAND-OPTIONS]

      Show the association shrub for INSTANCENAME.

      The shrub is a view of all of the instance association relationships for a defined INSTANCENAME showing the various
      components that are part of the association including Role, AssocClasse,ResultRole, And ResultClas

      The default view is a tree view from the INSTANCENAME to associated instances.

      Displays the shrub of association components for the association source instance defined by INSTANCENAME.

      For information on how to specify the instance using INSTANCENAME and the --key and --namespace options, invoke with
      --help-instancename.

      Normally the association information is displayed as a tree but it may also be displayed as a table or as one of the
      object formats (ex. MOF) of all instances that are part of the shrub if one of the cim object formats is selected
      with the global output_format parameter.

      Results are formatted as defined by the output format global option.

    Command Options:
      --ac, --assoc-class CLASSNAME   Filter the result set by association class name. Subclasses of the specified class
                                      also match.

      --rc, --result-class CLASSNAME  Filter the result set by result class name. Subclasses of the specified class also
                                      match.

      -r, --role PROPERTYNAME         Filter the result set by source end role name.
      --rr, --result-role PROPERTYNAME
                                      Filter the result set by far end role name.
      -k, --key KEYNAME=VALUE         Value for a key in keybinding of CIM instance name. May be specified multiple times.
                                      Allows defining keys without the issues of quotes. Default: No keybindings provided.

      -n, --namespace NAMESPACE       Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary                   Show only a summary (count) of the objects.
      -f, --fullpath                  Normally the instance paths in the tree views are by hiding some keys with ~ to make
                                      the tree simpler to read. This includes keys that have the same value for all
                                      instances and the "CreationClassName" key.  Whenthis option is used the full instance
                                      paths are displayed.

      --hi, --help-instancename       Show help message for specifying INSTANCENAME including use of the --key and
                                      --namespace options.

      -h, --help                      Show this help message.


.. _`pywbemcli namespace --help`:

pywbemcli namespace --help
--------------------------



Help text for ``pywbemcli namespace`` (see :ref:`namespace command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] namespace COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for CIM namespaces.

      This command group defines commands to create, delete and list namespaces in a WBEM server.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'namespace' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      list     List the namespaces of the server.
      create   Create a namespace on the server.
      delete   Delete a namespace from the server.
      interop  Get the Interop namespace of the server.


.. _`pywbemcli namespace create --help`:

pywbemcli namespace create --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli namespace create`` (see :ref:`namespace create command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] namespace create NAMESPACE [COMMAND-OPTIONS]

      Create a namespace on the server.

      Leading and trailing slash (``/``) characters specified in the NAMESPACE argument will be stripped.

      The namespace must not yet exist on the server.

      The Interop namespace must exist on the server and cannot be created using this command, because that namespace is
      required to implement client requests to manage namespaces.

      WBEM servers may not allow this operation or may severely limit the conditions under which a namespace can be
      created on the server.

      Example:

        pywbemcli -n myconn namespace create root/cimv2

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli namespace delete --help`:

pywbemcli namespace delete --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli namespace delete`` (see :ref:`namespace delete command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] namespace delete NAMESPACE [COMMAND-OPTIONS]

      Delete a namespace from the server.

      Leading and trailing slash (``/``) characters specified in the NAMESPACE argument will be stripped.

      The Interop namespace must exist on the server and cannot be deleted using this command.

      The targeted namespace must exist on the server. If the namespace contains any objects (qualifier types, classes or
      instances), the command is rejected unless the --include-objects option is specified.

      If the --include-objects option is specified, the dependency order of classes is determined, and the instances are
      deleted first in that order, then the classes in that order, and at last the qualifier types. This ensures that no
      dangling dependencies remain at any point in the operation. Dependencies that are considered for this purpose are
      subclasses, referencing classes and embedding classes (EmbeddedInstance qualifier only). Cross-namespace
      associations are deleted in the targeted namespace and are assumed to be properly handled by the server in the other
      namespace. (i.e. to be cleaned up there as well without requiring a deletion by the client).

      WARNING: Deletion of instances will cause the removal of corresponding resources in the managed environment (i.e. in
      the real world). Some instances may not be deletable.

      WARNING: Deletion of classes or qualifier types can cause damage to the server: It can impact instance providers and
      other components in the server. WBEM servers may not allow the deletion of classes or qualifier declarations.

      WBEM servers may not allow deletion of namespaces or may severely limit the conditions under which a namespace can
      be deleted.

      Example:

        pywbemcli -n myconn namespace delete root/cimv2

    Command Options:
      --include-objects  Delete any objects in the namespace as well. WARNING: Deletion of instances will cause the removal
                         of corresponding resources in the managed environment (i.e. in the real world). Default: Reject
                         command if the namespace has any objects.

      --dry-run          Enable dry-run mode: Do not actually delete the objects, but display what would be done.
      -h, --help         Show this help message.


.. _`pywbemcli namespace interop --help`:

pywbemcli namespace interop --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli namespace interop`` (see :ref:`namespace interop command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] namespace interop [COMMAND-OPTIONS]

      Get the Interop namespace of the server.

      The Interop namespace must exist on the server.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli namespace list --help`:

pywbemcli namespace list --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli namespace list`` (see :ref:`namespace list command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] namespace list [COMMAND-OPTIONS]

      List the namespaces of the server.

      The Interop namespace must exist on the server.

      Examples:

        pywbemcli -n myconn namespace list

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli profile --help`:

pywbemcli profile --help
------------------------



Help text for ``pywbemcli profile`` (see :ref:`profile command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] profile COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for WBEM management profiles.

      This command group defines commands to inspect and manage the WBEM management profiles maintained by the WBEM
      server.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'server' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      list          List WBEM management profiles advertised by the server.
      centralinsts  List WBEM management profile central instances on the server.


.. _`pywbemcli profile centralinsts --help`:

pywbemcli profile centralinsts --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli profile centralinsts`` (see :ref:`profile centralinsts command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] profile centralinsts [COMMAND-OPTIONS]

      List WBEM management profile central instances on the server.

      Retrieve the CIM instances that are central instances of the specified WBEM management profiles, and display these
      instances. By default, all management profiles advertized on the server are included. The profiles can be filtered
      by using the --organization and --profile options.

      The central instances are determined using all methodologies defined in DSP1033 V1.1 in the order of
      GetCentralInstances, central class, and scoping class methodology.

      Profiles that only use the scoping class methodology require the specification of the --central-class, --scoping-
      class, and --scoping-path options because additional information is needed to perform the scoping class methodology.

      The retrieved central instances are displayed along with the organization, name, and version of the profile they
      belong to, formatted as a table. The --output-format general option is ignored unless it specifies a table format.

    Command Options:
      -o, --organization ORG-NAME     Filter by the defined organization. (ex. -o DMTF
      -p, --profile PROFILE-NAME      Filter by the profile name. (ex. -p Array
      --cc, --central-class CLASSNAME
                                      Optional. Required only if profiles supports only scoping methodology
      --sc, --scoping-class CLASSNAME
                                      Optional. Required only if profiles supports only scoping methodology
      --sp, --scoping-path CLASSLIST  Optional. Required only if profiles supports only scoping methodology. Multiples
                                      allowed

      --rd, --reference-direction [snia|dmtf]
                                      Navigation direction for association.  [default: dmtf]
      -h, --help                      Show this help message.


.. _`pywbemcli profile list --help`:

pywbemcli profile list --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli profile list`` (see :ref:`profile list command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] profile list [COMMAND-OPTIONS]

      List WBEM management profiles advertised by the server.

      Retrieve  the WBEM management profiles advertised by the WBEM server, and display information about each profile.
      WBEM management profiles are defined by DMTF and SNIA and define the management functionality that is available.

      The retrieved profiles can be filtered using the --organization and --profile options.

      The output is formatted as a table showing the organization, name, and version for each profile. The --output-format
      option is ignored unless it specifies a table format.

    Command Options:
      -o, --organization ORG-NAME  Filter by the defined organization. (ex. -o DMTF
      -p, --profile PROFILE-NAME   Filter by the profile name. (ex. -p Array
      -h, --help                   Show this help message.


.. _`pywbemcli qualifier --help`:

pywbemcli qualifier --help
--------------------------



Help text for ``pywbemcli qualifier`` (see :ref:`qualifier command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] qualifier COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for CIM qualifier declarations.

      This command group defines commands to inspect and delete CIM qualifier declarations in the WBEM Server.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'qualifier' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      get        Get a qualifier declaration.
      delete     Delete a qualifier declaration.
      enumerate  List the qualifier declarations in a namespace.


.. _`pywbemcli qualifier delete --help`:

pywbemcli qualifier delete --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli qualifier delete`` (see :ref:`qualifier delete command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] qualifier delete QUALIFIERNAME [COMMAND-OPTIONS]

      Delete a qualifier declaration.

      Delete a CIM qualifier declaration (QUALIFIERNAME argument) in a CIM namespace (--namespace option). If no namespace
      was specified, the default namespace of the connection is used.

      This command executes the DeleteQualifier operation against the WBEM server and leaves it to the WBEM server to
      reject the operation if any classes in the namespace use the qualifier.

      In the output, the qualifier declaration will formatted as defined by the --output-format general option.

    Command Options:
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                 Show this help message.


.. _`pywbemcli qualifier enumerate --help`:

pywbemcli qualifier enumerate --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli qualifier enumerate`` (see :ref:`qualifier enumerate command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] qualifier enumerate [COMMAND-OPTIONS]

      List the qualifier declarations in a namespace.

      Enumerate the CIM qualifier declarations in the specified CIM namespace (--namespace option). If no namespace was
      specified, the default namespace of the connection is used.

      In the output, the qualifier declaration will formatted as defined by the --output-format general option.

    Command Options:
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -s, --summary              Show only a summary (count) of the objects.
      -h, --help                 Show this help message.


.. _`pywbemcli qualifier get --help`:

pywbemcli qualifier get --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli qualifier get`` (see :ref:`qualifier get command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] qualifier get QUALIFIERNAME [COMMAND-OPTIONS]

      Get a qualifier declaration.

      Get a CIM qualifier declaration (QUALIFIERNAME argument) in a CIM namespace (--namespace option). If no namespace
      was specified, the default namespace of the connection is used.

      In the output, the qualifier declaration will formatted as defined by the --output-format general option.

    Command Options:
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -h, --help                 Show this help message.


.. _`pywbemcli repl --help`:

pywbemcli repl --help
---------------------



Help text for ``pywbemcli repl`` (see :ref:`repl command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] repl

      Enter interactive mode (default).

      Enter the interactive mode where pywbemcli commands can be entered interactively. The prompt is changed to
      'pywbemcli>'.

      Command history is supported. The command history is stored in a file ~/.pywbemcli_history.

      Pywbemcli may be terminated from this mode by entering <CTRL-D>, :q, :quit, :exit

      In the repl mode, <CTRL-r> man be used to initiate an interactive search of the history file.

      Interactive mode also includes an autosuggest feature that makes suggestions from the command history as the command
      the user types in the command and options.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli server --help`:

pywbemcli server --help
-----------------------



Help text for ``pywbemcli server`` (see :ref:`server command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for WBEM servers.

      This command group defines commands to inspect and manage core components of a WBEM server including server
      attributes, namespaces, compiling MOF, the Interop namespace, management profiles, and access to profile central
      instances.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'server' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      namespaces  List the namespaces of the server (deprecated).
      interop     Get the Interop namespace of the server (deprecated).
      brand       Get the brand of the server.
      info        Get information about the server.
      add-mof     Compile MOF and add/update CIM objects in the server.
      remove-mof  Compile MOF and remove CIM objects from the server.


.. _`pywbemcli server add-mof --help`:

pywbemcli server add-mof --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server add-mof`` (see :ref:`server add-mof command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server add-mof MOFFILE [COMMAND-OPTIONS]

      Compile MOF and add/update CIM objects in the server.

      The MOF files are specified with the MOFFILE argument, which may be specified multiple times. The minus sign ('-')
      specifies the standard input.

      Initially, the target namespace is the namespace specified with the --namespace option or if not specified the
      default namespace of the connection. If the MOF contains '#pragma namespace' directives, the target namespace will
      be changed accordingly.

      MOF include files (specified with the '#pragma include' directive) are searched first in the directory of the
      including MOF file, and then in the directories specified with the --include option.

      Any CIM objects (instances, classes and qualifiers) specified in the MOF files are created in the server, or
      modified if they already exist in the server.

      The global --verbose option will show the CIM objects that are created or modified.

    Command Options:
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -I, --include INCLUDEDIR   Path name of a MOF include directory. May be specified multiple times.
      -d, --dry-run              Enable dry-run mode: Don't actually modify the server. Connection to the server is still
                                 required for reading.

      -h, --help                 Show this help message.


.. _`pywbemcli server brand --help`:

pywbemcli server brand --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server brand`` (see :ref:`server brand command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server brand [COMMAND-OPTIONS]

      Get the brand of the server.

      Brand information is defined by the server implementor and may or may not be available. Pywbem attempts to collect
      the brand information from multiple sources.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli server info --help`:

pywbemcli server info --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server info`` (see :ref:`server info command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server info [COMMAND-OPTIONS]

      Get information about the server.

      The information includes CIM namespaces and server brand.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli server interop --help`:

pywbemcli server interop --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server interop`` (see :ref:`server interop command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server interop [COMMAND-OPTIONS]

      Get the Interop namespace of the server (deprecated).

      The Interop namespace must exist on the server.

      Deprecated: The 'server interop' command is deprecated and will be removed in a future version. Use the 'namespace
      interop' command instead.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli server namespaces --help`:

pywbemcli server namespaces --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server namespaces`` (see :ref:`server namespaces command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server namespaces [COMMAND-OPTIONS]

      List the namespaces of the server (deprecated).

      The Interop namespace must exist on the server.

      Deprecated: The 'server namespaces' command is deprecated and will be removed in a future version. Use the
      'namespace list' command instead.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli server remove-mof --help`:

pywbemcli server remove-mof --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli server remove-mof`` (see :ref:`server remove-mof command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] server remove-mof MOFFILE [COMMAND-OPTIONS]

      Compile MOF and remove CIM objects from the server.

      The MOF files are specified with the MOFFILE argument, which may be specified multiple times. The minus sign ('-')
      specifies the standard input.

      Initially, the target namespace is the namespace specified with the --namespace option or if not specified the
      default namespace of the connection. If the MOF contains '#pragma namespace' directives, the target namespace will
      be changed accordingly.

      MOF include files (specified with the '#pragma include' directive) are searched first in the directory of the
      including MOF file, and then in the directories specified with the --include option.

      Any CIM objects (instances, classes and qualifiers) specified in the MOF files are deleted from the server.

      The global --verbose option will show the CIM objects that are removed.

    Command Options:
      -n, --namespace NAMESPACE  Namespace to use for this command, instead of the default namespace of the connection.
      -I, --include INCLUDEDIR   Path name of a MOF include directory. May be specified multiple times.
      -d, --dry-run              Enable dry-run mode: Don't actually modify the server. Connection to the server is still
                                 required for reading.

      -h, --help                 Show this help message.


.. _`pywbemcli statistics --help`:

pywbemcli statistics --help
---------------------------



Help text for ``pywbemcli statistics`` (see :ref:`statistics command group`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics COMMAND [ARGS] [COMMAND-OPTIONS]

      Command group for WBEM operation statistics.

      This command group defines commands to control the gathering and display of statistical data about the WBEM
      operations issued by pywbemcli or processed by a WBEM server.

      Pywbemcli maintains statistics about the WBEM operations it has issued. This includes the Client Time measured on
      the client side and the Server Time measured by the WBEM server and reported in the 'WBEMServerResponseTime' header
      field in the CIM-XML response (if supported by the WBEM server).

      The WBEM server may also support maintaining statistics about the WBEM operations it has processed (possibly by
      multiple clients). Pywbemcli supports enabling or disabling the statistics gathering on the WBEM server via the
      'GatherStatisticalData' property in the 'CIM_ObjectManager' instance for the WBEM server and supports retrieving and
      displaying the server maintained statistics.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the 'statistics' keyword.

    Command Options:
      -h, --help  Show this help message.

    Commands:
      reset        Reset client maintained statistics.
      server-on    Enable server maintained statistics.
      server-off   Disable server maintained statistics.
      server-show  Display server maintained statistics.
      show         Display client maintained statistics.
      status       Show enabled status of client and server maintained statistics.


.. _`pywbemcli statistics reset --help`:

pywbemcli statistics reset --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics reset`` (see :ref:`statistics reset command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics reset [COMMAND-OPTIONS]

      Reset client maintained statistics.

      This command resets the counts in the statistics maintained by pywbemcli. This includes the server response times
      received from the WBEM server in the 'WBEMServerResponseTime' header field of the CIM-XML response, if supported and
      enabled.

      This command does not reset the server maintained statistics.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli statistics server-off --help`:

pywbemcli statistics server-off --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics server-off`` (see :ref:`statistics server-off command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics server-off [COMMAND-OPTIONS]

      Disable server maintained statistics.

      This command deactivates the gathering of statistics in the current WBEM server and also deactivates the returning
      of server response times in the CIM-XML response for inclusion in the client maintained statistics, by setting the
      'GatherStatisticalData' property to False in the 'CIM_ObjectManager' instance for the WBEM server.

      This command fails if the server does not support gathering statistics or does not allow a client to modify the
      state of statistics gathering.

      This command does not affect the state of the client maintained statistics other than whether the server response
      times are included. See the '--timestats' general option for controlling the displaying of client maintained
      statistics.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli statistics server-on --help`:

pywbemcli statistics server-on --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics server-on`` (see :ref:`statistics server-on command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics server-on [COMMAND-OPTIONS]

      Enable server maintained statistics.

      This command activates the gathering of statistics in the current WBEM server and also activates the returning of
      server response times in the CIM-XML response for inclusion in the client maintained statistics, by setting the
      'GatherStatisticalData' property to True in the 'CIM_ObjectManager' instance for the WBEM server.

      This command fails if the server does not support gathering statistics or does not allow a client to modify the
      state of statistics gathering.

      This command does not affect the state of the client maintained statistics other than whether the server response
      times are included. See the '--timestats' general option for controlling the displaying of client maintained
      statistics.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli statistics server-show --help`:

pywbemcli statistics server-show --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics server-show`` (see :ref:`statistics server-show command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics server-show [COMMAND-OPTIONS]

      Display server maintained statistics.

      Retrieve and display the statistics gathered by the current WBEM server. This requires statistics gathering to be
      enabled on the server (see 'statistics server-on' command).

      This command fails if the server does not support gathering statistics.

      These statistics are independent of the client maintained statistics which can be displayed with the command
      'statistics show'.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli statistics show --help`:

pywbemcli statistics show --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics show`` (see :ref:`statistics show command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics show [COMMAND-OPTIONS]

      Display client maintained statistics.

      Display the statistics gathered by pywbemcli. This includes the server response times received from the WBEM server
      in the 'WBEMServerResponseTime' header field of the CIM-XML response, if supported and enabled.

      These statistics are independent of the server maintained statistics which can be displayed with the command
      'statistics server-show'.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli statistics status --help`:

pywbemcli statistics status --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli statistics status`` (see :ref:`statistics status command`):


::

    Usage: pywbemcli [GENERAL-OPTIONS] statistics status [COMMAND-OPTIONS]

      Show enabled status of client and server maintained statistics.

      Show the enabled status for displaying the statistics gathered by pywbemcli, and for gathering the statistics on the
      current WBEM server.

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli subscription --help`:

pywbemcli subscription --help
-----------------------------



Help text for ``pywbemcli subscription`` (see :ref:`subscription command group`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription COMMAND [ARGS]...

      Command group to manage WBEM subscriptions.

      This group uses the pywbem subscription manager to view and manage CIM Indication subscripitons for a WBEM Server.

      In addition to the command-specific options shown in this help text, the general options (see 'pywbemcli --help')
      can also be specified before the command. These are NOT retained after the command is executed.

    Command Options:
      -h, --help  Show this message and exit.

    Commands:
      add-destination      TODO: modify to allow adding multiple destinations by repeating url option Create a new...
      add-filter           Add a new indication filter.
      add-subscription     Add a new indication subscription.
      list                 List indication subscriptions.
      list-destinations    list subscription destinations objects List the existing CIM indication destinations on the...
      list-filters         list subscription filters.
      list-subscriptions   Show indication subscription overview.
      remove-destination   Delete a destination from the server The destination to be removed can be idenitified by TODO
      remove-filter        Remove a subscription filter.
      remove-server        Remove the server identified by the server_id.
      remove-subscription  Remove indication subscription(s) from a WBEM server, by deleting the indication subscription...
      test-indication      Generate test indications.


.. _`pywbemcli subscription add-destination --help`:

pywbemcli subscription add-destination --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription add-destination`` (see :ref:`subscription add-destination command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription add-destination

      TODO: modify to allow adding multiple destinations by repeating url option Create a new listener destination.

      The listener destination defines the location of a WBEM indication listener and includes all the parameters to
      define that listener.

      This command automatically creates a listener destination instance (of CIM class "CIM_ListenerDestinationCIMXML")
      for each specified listener URL in the Interop namespace of the specified WBEM server.

      The listener destination is automatically created on the target WBEM connection.

    Command Options:
      -l, --listener-url URI  Add a listener destination url for indications. this includes the schema (http or https, the
                              host name and the listener port

      --owned                 Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -h, --help              Show this help message.


.. _`pywbemcli subscription add-filter --help`:

pywbemcli subscription add-filter --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription add-filter`` (see :ref:`subscription add-filter command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription add-filter

      Add a new indication filter.

      This command adds a :term:`dynamic indication filter` to a WBEM server, by creating an indication filter instance
      (of CIM class "CIM_IndicationFilter") in the Interop namespace of the server.

      The new indication filter is defined by the input parameters.  If the options are --owned and --filter_id, the
      filter is only added if there is no filter with the same filter_id in the WBEM server. Otherwise, the existing
      filter with the defined_filter_id is modified

      if --owned is not specified, either the --filter-id or --name parameter may be used to define the filter ``Name``
      property.

      The --name option should be used in cases where the user needs to have control over the filter name (e.g. because a
      DMTF management profile requires a particular name), but it cannot be used for owned filters.

      Owned indication filters are added or updated conditionally: If the indication filter instance to be added is
      already registered with this subscription manager and has the same property values, it is not created or modified.
      If it has the same path but different property values, it is modified to get the desired property values. If an
      instance with this path does not exist yet (the normal case), it is created.

      Permanent indication filters are created unconditionally, and it is up to the user to ensure that such an instance
      does not exist yet.

    Command Options:
      -q, --query filter       Filter query definition. This is a SELECT statement in the query language defined in the
                               filter-query-language parameter

      --query-language TEXT    Filter query language for this subscription The query languages normally implemented are
                               "DMTF:CQL" and "WQL" .  Default: WQL

      --source-namespace TEXT  The namespace for which the query is defined. If not  defined, the default namespace of the
                               server is used

      --name TEXT              Value for the name parameter.
      --filter-id TEXT         Text that is used to define the name parameter.
      --owned                  Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -h, --help               Show this help message.


.. _`pywbemcli subscription add-subscription --help`:

pywbemcli subscription add-subscription --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription add-subscription`` (see :ref:`subscription add-subscription command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription add-subscription

      Add a new indication subscription.

      Add a subscription to a WBEM server defined by the server_id for a particular set of indications defined by an
      indication filter and for a particular WBEM listener defined by the instance path of the listener destinations, by
      creating indication subscription instances (of CIM class "CIM_IndicationSubscription") in the Interop namespace of
      the server.

      The specified indication filter may be owned, permanent or static.

      The specified listener destinations may be owned, permanent or static.

      When creating permanent subscriptions, the indication filter and the listener destinations must not be owned.

      Owned subscriptions are added or updated conditionally: If the subscription instance to be added is already
      registered with this subscription manager and has the same path , it is not created.

      Permanent subscriptions are created unconditionally, and it is up to the user to ensure that such an instance does
      not exist yet.

      Upon successful return of this method, the added subscription is active, so that the specified WBEM listeners may
      immediately receive indications.

    Command Options:
      --select    Select filter and destination to include in this subscription.
      --owned     Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -h, --help  Show this help message.


.. _`pywbemcli subscription list --help`:

pywbemcli subscription list --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription list`` (see :ref:`subscription list command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription list

      List indication subscriptions.

      This command provides an overview of the subscriptions, filters, and destinations

    Command Options:
      --owned        Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -d, --detail   Show all properties of the instances. Otherwise only non-null or predefined property values are
                     displayed

      -p, --paths    Show CIMInstanceName elements of the instances.
      -s, --summary  If True, show only summary count of instances
      -h, --help     Show this help message.


.. _`pywbemcli subscription list-destinations --help`:

pywbemcli subscription list-destinations --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription list-destinations`` (see :ref:`subscription list-destinations command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription list-destinations

      list subscription destinations objects

      List the existing CIM indication destinations on the current connection

    Command Options:
      --owned        Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -d, --detail   Show all properties of the instances. Otherwise only non-null or predefined property values are
                     displayed

      -p, --paths    Show CIMInstanceName elements of the instances.
      -s, --summary  If True, show only summary count of instances
      -h, --help     Show this help message.


.. _`pywbemcli subscription list-filters --help`:

pywbemcli subscription list-filters --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription list-filters`` (see :ref:`subscription list-filters command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription list-filters

      list subscription filters.

      List existing CIM indication subscriptions on the current connection

    Command Options:
      --name TEXT       Value for the name parameter.
      --filter-id TEXT  Text that is used to define the name parameter.
      --owned           Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -d, --detail      Show all properties of the instances. Otherwise only non-null or predefined property values are
                        displayed

      -p, --paths       Show CIMInstanceName elements of the instances.
      -s, --summary     If True, show only summary count of instances
      -h, --help        Show this help message.


.. _`pywbemcli subscription list-subscriptions --help`:

pywbemcli subscription list-subscriptions --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription list-subscriptions`` (see :ref:`subscription list-subscriptions command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription list-subscriptions

      Show indication subscription overview.

      This command displays an overview the owned subscriptions, filters, and destinations.

      It displays the instances using the detail paths, or summary options

    Command Options:
      --owned        Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -d, --detail   Show all properties of the instances. Otherwise only non-null or predefined property values are
                     displayed

      -p, --paths    Show CIMInstanceName elements of the instances.
      -s, --summary  If True, show only summary count of instances
      -h, --help     Show this help message.


.. _`pywbemcli subscription remove-destination --help`:

pywbemcli subscription remove-destination --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription remove-destination`` (see :ref:`subscription remove-destination command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-destination

      Delete a destination from the server

      The destination to be removed  can be idenitified by TODO

    Command Options:
      -n, --path destination  Delete by path name of the filter.
      --select                Select filter to delete from select list of filters.
      --owned                 Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -h, --help              Show this help message.


.. _`pywbemcli subscription remove-filter --help`:

pywbemcli subscription remove-filter --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription remove-filter`` (see :ref:`subscription remove-filter command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-filter

      Remove a subscription filter.

      Filters to be removed are identified by either the filter_id or the name parameter and whether they are owned or now

      The --select option allows the user to get a list of the paths of filters and selecting one to be removed

    Command Options:
      --select          Select filter to delete from select list of filters.
      --name TEXT       Value for the name parameter.
      --filter-id TEXT  Text that is used to define the name parameter.
      --owned           Limit the operation to owned subscriptions, listener destinations or filters. Default: False
      -h, --help        Show this help message.


.. _`pywbemcli subscription remove-server --help`:

pywbemcli subscription remove-server --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription remove-server`` (see :ref:`subscription remove-server command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-server

      Remove the server identified by the server_id. This command also unregisters listeners from these servers and
      removes all owned indication subscriptions, owned indication filters, and owned listener destinations

    Command Options:
      -h, --help  Show this help message.


.. _`pywbemcli subscription remove-subscription --help`:

pywbemcli subscription remove-subscription --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription remove-subscription`` (see :ref:`subscription remove-subscription command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription remove-subscription

      Remove indication subscription(s) from a WBEM server, by deleting the indication subscription instances in the
      server.

      The indication subscriptions must be owned or permanent (i.e. not static).

      This operation does not remove the associated filter or destination instances.

    Command Options:
      --select    Select filter to delete from select list of filters.
      -h, --help  Show this help message.


.. _`pywbemcli subscription test-indication --help`:

pywbemcli subscription test-indication --help
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^



Help text for ``pywbemcli subscription test-indication`` (see :ref:`subscription test-indication command`):


::

    Usage: pywbemcli [COMMAND-OPTIONS] subscription test-indication

      Generate test indications.  This command executes a WBEM server dependent set of requests to generate test
      indications.

      Today, it only works for the OpenPegasus WBEM server and only if specific classes are implemented in a provider on
      the server.  It creates an owned subscription and sends a method that tells the server to generate a number of test
      indications.

      If the owned option is set, the command will issue a message and wait for the user and then complete which will
      close the subscription.  If not owned, the user must later delete the subscription.

    Command Options:
      -l, --listener-url URI  Listener destination url for indications. Default:http://localhost:25989
      --count COUNT           Number of test indications to be requested. Default:10.
      -h, --help              Show this help message.

