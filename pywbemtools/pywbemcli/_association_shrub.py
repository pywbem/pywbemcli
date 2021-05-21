# (C) Copyright 2019 IBM Corp.
# (C) Copyright 2019 Inova Development Inc.
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
Class to represent the concept and implementation of an association shrub.

A shrub is a view of association relations that gathers and presents all of the
information about a relation including the roles, reference classes, result
roles and result classes that may return instances. I differs from the
associator and reference commands in that they present the user with just a set
of CIM objects or their names, and not a view of the relations between the
components that make up a CIM association.

It is based on the parameters of the pywbem associators operation including
role, AssocClass, ResultRole, ResultClass. A shrub request that does not
include  these options, returns all possible relations of the association.
If any of the these optional parameters are included, only the names included
in the option are considered as the result is prepared.

It builds the information by using the reference and association operations to
gather data from the server and present either a table or tree view of
the relations that link a source instance and the target instances of an
association.
"""


from __future__ import absolute_import, print_function, unicode_literals

from collections import defaultdict, OrderedDict, namedtuple
import six
import click

from asciitree import LeftAligned
from pywbem import CIMClassName, CIMError
from pywbem._nocasedict import NocaseDict

from ._common import shorten_path_str, sort_cimobjects, to_wbem_uri_folded
from .._utils import get_terminal_width
from .._output_formatting import output_format_is_table, format_table, \
    warning_msg

# Same as in pwbem.cimtypes.py
if six.PY2:
    # pylint: disable=invalid-name,undefined-variable
    _Longint = long  # noqa: F821
else:
    # pylint: disable=invalid-name
    _Longint = int

# Named tuple defining an Association class name and corresponding
# integer representing the Reference instance for that association. Used
# to display information about reference instances for associations with
# more than 2 reference properties.
AssocNameTuple = namedtuple('AssocName', 'Name, RefInst')


def _match_instname_wo_host(instance_name1, instance_name2):
    """
    Test 2 instance names for equality ignoring the host name. Creates copy
    to avoid changing input instance names.
    """
    in1 = instance_name1.copy()
    in2 = instance_name2.copy()
    in1.host = None
    in2.host = None
    return in1 == in2


class AssociationShrub(object):
    # pylint: disable=useless-object-inheritance, too-many-instance-attributes
    """
    This class provides tools for the acquisition and display of an association
    that includes much more information than the DMTF defined operation
    Associatiors.  Using the same input parameters, it allows displaying
    the components that make up an association as either a table or a
    tree including the reference classes, and roles.

    This class does not handle Error exceptions from the host WBEM Server.
    They must be handled by the user.
    """
    def __init__(self, conn, source_path, Role=None, AssocClass=None,
                 ResultRole=None, ResultClass=None, fullpath=True,
                 verbose=None):
        """
        Parameters:

          conn (:class:`~pywbem.WBEMConnection`):
            The current connection object.

          source_path (:class:`CIMInstanceName`):
            Source instance path for the reference and association lookup. This
            may include namespace and host name but the host name is ignored.
            This is the same source as an associators or references call.

          Role (:term:`string):
            See pywbem Associators for the definition of this parameter


          AssocClass (:term:`string`):
            See pywbem Associators for the definition of this parameter

          ResultRole (:term:`string):
            See pywbem Associators for the definition of this parameter

          ResultClass (:term:`string`):
            See pywbem Associators for the definition of this parameter

          fullpath (:class:`py:bool`):
            If True, the full path of instances is displayed

        Raises:
           Error: If the server returns exceptions
        """

        # set the host to None. We already know that is is our host
        source_path.host = None
        self.source_path = source_path
        self.conn = conn

        self.role = Role
        self.assoc_class = AssocClass
        self.result_role = ResultRole
        self.result_class = ResultClass

        self.fullpath = fullpath
        self.verbose = verbose

        #  Dictionary view of the shrub. This is a dictionary of dictionaries
        #  role:ReferenceClassNames:
        #  NOTE: OrderedDict assures that table and tree output order is
        #  deterministic.
        self.instance_shrub = OrderedDict()

        # associated instance names dictionary organized by:
        #   - reference_class,
        #   - role,
        #   - associated class
        # NOTE: To account for issues where there is an error getting data from
        # host, the concept of a "None" role exists.
        self.assoc_instnames = OrderedDict()

        self.source_namespace = source_path.namespace or \
            self.conn.default_namespace
        self.source_host = source_path.host or self.conn.host
        # Copy of source_path with namespace
        self.full_source_path = self.source_path.copy()
        if self.full_source_path.namespace is None:
            self.full_source_path.namespace = self.source_namespace

        # Cache the results of conn.ReferenceNames(self.source+path)
        self.reference_names = None

        self.ternary_ref_classes = OrderedDict()

        # Build the shrub dictionary for the instance defined by
        # self.source_path
        self._build_instance_shrub()

    @property
    def reference_classnames(self):
        """
        Return a list of the reference class names in the current shrub.
        This returns a list of objects of the class pywbem:CIMClassname
        which contains the name, host, and namespace for each class.
        """
        # pylint: disable=unnecessary-comprehension
        return [cln for cln in self.instance_shrub]

    def sorted_references(self, source_path):
        """
        Get reference instances from host sorted by instance name

        Parameters:

          source_path (:class:`pywbem:CIMInstancePath):
            Source path for the References request to the host

        Returns:
           list of :class:`pywbem:CIMClassNames` returns from host

        Raises:
            Error if Error returned from host
        """
        reference_instances = self.conn.References(source_path)
        return sort_cimobjects(reference_instances)

    def sorted_associator_names(self, source_path, role=None, assoc_class=None,
                                result_role=None, result_class=None):
        """
        Get associated instances from host sorted by instance name.

        Parameters:

          source_path (:class:`pywbem:CIMInstancePath):

          role (:term:`string`):
            Optional string defining Role parameter of the Associators
            call to the host

          assoc_class (:class:`pywbem:CIMClass`):
            Optional string defining ResutRole parameter of the Associators
            call to the host.

          result_role (:term:`string`):
            Optional string defining ResutRole parameter of the Associators
            call to the host

          result_class (:class:`pywbem:CIMClass`):
            Optional string defining ResutRole parameter of the Associators
            call to the host

        Returns:
           list of :class:`pywbem:CIMClassNames` returns from host

        Raises:
            Error if error returned from host webserver
        """

        rtnd_assoc_inames = self.conn.AssociatorNames(
            source_path,
            Role=role,
            AssocClass=assoc_class,
            ResultRole=result_role,
            ResultClass=result_class)
        return sort_cimobjects(rtnd_assoc_inames)

    def _build_instance_shrub(self):
        """
        Build the internal representation of a tree for the shrub as a
        dictionary of dictionaries representing the tree. This builds the shrub
        dictionary (self.instance_shrub) from the top of the tree down to
        the bottom.
        """
        # Build CIMClassname with host, namespace and insert if not
        # already in class_roles dictionary. Get the instance from
        # the host and roles from the instance.
        # ref_class_roles dictionary {<cln>:[roles]}
        ref_insts = self.sorted_references(self.source_path)

        self.define_ternary_references(ref_insts)

        # Build list of reference CIMClassName objects and add to a
        # ref_class_roles dict
        # Test for input --AssocClass parameter and limit ref names to this
        # class if it exists and is one of the defined classes
        reference_instnames = [i.path for i in ref_insts]

        if self.assoc_class:
            # Test if AssocClass parameter represents class in rtnd references
            if self.assoc_class.lower() in {n.classname.lower()
                                            for n in reference_instnames}:
                reference_instnames = [rn for rn in reference_instnames if
                                       self.assoc_class.lower() ==
                                       rn.classname.lower()]
            else:
                reference_instnames = [i.path for i in ref_insts]
                ref_clns = {n.classname for n in reference_instnames}
                warning_msg(
                    'Option --assoc-name "{}" not found in associator names '
                    '({})" from server'.format(self.assoc_class,
                                               ", ".join(ref_clns)))

        # Add the reference classes to the ref_class_roles dict
        ref_class_roles = OrderedDict()
        for ref in reference_instnames:
            cln = CIMClassName(ref.classname, ref.host, ref.namespace)
            if cln not in ref_class_roles:
                roles = self._get_reference_roles(ref)
                if roles:
                    ref_class_roles[cln] = roles

        # Find role parameter and insert into instance_shrub dictionary.
        # The result is dictionary of form:
        #   {<role>:{<ASSOC_CLASS>:[RESULTROLES]}
        for cln, roles in six.iteritems(ref_class_roles):
            role_dict = self._get_role_result_roles(roles, cln.classname)

            # Insert the role and cln into the shrub_dict
            for role, result_roles in role_dict.items():
                if role not in self.instance_shrub:
                    self.instance_shrub[role] = OrderedDict()

                # Put result_roles in shrub dict temporarily
                # Next code block converts value to
                if cln not in self.instance_shrub[role]:
                    self.instance_shrub[role][cln] = result_roles

        # If self.role exists, remove any unwanted roles from dict
        # Accounts for case differences between self.role and roles from
        # target server
        if self.role:
            tst_role = self.role.lower()
            # Test for --role as valid role for this request and do warning.
            roles = list(self.instance_shrub)
            if tst_role not in [r.lower() for r in roles]:
                warning_msg('Option --role ({}) not found in roles: ({}). '
                            'Ignored'.format(self.role, ', '.join(roles)))
            else:
                # Remove any roles not defined in self.role
                remove_roles = [r for r in roles if r.lower() != tst_role]
                if remove_roles:
                    for role in remove_roles:
                        del self.instance_shrub[role]

        # Find associated instances/classes for each role
        for role in self.instance_shrub:
            self.assoc_instnames[role] = OrderedDict()
            for ref_classname in self.instance_shrub[role]:
                # Get temp installed result roles from shrub_dict and
                # replace with defaultdict that is basis for next level
                result_roles = self.instance_shrub[role][ref_classname]

                # Create associator result dictionaries with ref_class as key
                self.assoc_instnames[role][ref_classname] = OrderedDict()
                self.instance_shrub[role][ref_classname] = defaultdict(list)

                # Get Associated class names by AssocClass and ResultRole
                assoc_clns = []
                for result_role in result_roles:
                    # Get the associated instance names from server for
                    # all result_classes
                    if self.result_role:
                        if self.result_role.lower() != result_role.lower():
                            continue

                    rtnd_assoc_inames = self.sorted_associator_names(
                        self.source_path,
                        role=role,
                        assoc_class=ref_classname.classname,
                        result_role=result_role)

                    # Build unique associated classnames from returned inames.
                    # This is full ClassName entities including ns, host with
                    # a set comprehension so only unique names are kept
                    rtnd_classnames = list({CIMClassName(iname.classname,
                                                         iname.host,
                                                         iname.namespace)
                                            for iname in rtnd_assoc_inames})

                    # Discard unwanted assoc classes if --result_class param
                    # defined
                    if self.result_class:
                        rc = self.result_class.lower()
                        # Define list of unique returned assoc classnames
                        filtered_clns = list({iname.classname.lower() for iname
                                              in rtnd_assoc_inames
                                              if iname.classname.lower() == rc})

                        # Discard unwanted assoc classes
                        rtnd_classnames = [cln for cln in rtnd_classnames if
                                           cln.classname.lower()
                                           in filtered_clns]

                    assoc_clns.extend(rtnd_classnames)

                    # Extend instance_shrub_dict with returned assoc classnames
                    # pylint: disable=line-too-long
                    self.instance_shrub[role][ref_classname][result_role].extend(rtnd_classnames)  # noqa: E501
                    # pylint: enable=line-too-long

                    # Get associated instance names by AssocClass, role and
                    # target name using the assoc_clns from above
                    disp_result_role = result_role or "None"
                    # Get AssociatorNames for specific ResultClass
                    for assoc_cln in assoc_clns:
                        assoc_inames = self.sorted_associator_names(
                            self.source_path,
                            role=role,
                            assoc_class=ref_classname.classname,
                            result_role=result_role,
                            result_class=assoc_cln.classname)

                        # Build namedtuple of name, ref_inst  integer.
                        # This ties each output instance to a particular
                        # reference instance.
                        self.build_assoc_name_tuples(
                            assoc_inames, assoc_cln,
                            disp_result_role, role, ref_classname,
                            ref_insts, result_role)

    def display_shrub(self, output_format, summary=None):
        """
        Build the shrub output and display it to the output device based on
        the output_format.
        The default ouput format is ascii tree
        """

        if output_format_is_table(output_format):
            click.echo(self.build_shrub_table(output_format, summary))

        # default is display as ascii tree
        else:
            click.echo(self.build_ascii_display_tree(summary))

    def build_ascii_display_tree(self, summary):
        """
        Build ascii tree display for current shrub.
        Returns an String with the formatted ASCII tree
        """
        tree = self.build_shrub_tree(summary)

        tr = LeftAligned()
        return tr(tree)

    def build_shrub_tree(self, summary):
        """
        Prepare an ascii tree form of the shrub showing the hiearchy of
        components of the shrub. The top is the association source instance.
        The levels of the tree are:
            source instance
                role
                    reference_classe
                        result_role
                            result_classe
                                result_instances
        The dictionaries that define the tree are built from the bottom up
        based on the shrub_dict and use OrderedDict to preserve order
        of the items.
        """
        assoctree = OrderedDict()
        # Create dictionary of standard instance keys to potentially hide.
        # For now we always hide the following independent of key value
        replacements = NocaseDict((("SystemCreationClassName", None),
                                   ("SystemName", None)))
        for role, ref_clns in six.iteritems(self.instance_shrub):
            elementstree = OrderedDict()
            for ref_cln in ref_clns:
                rrole_dict = OrderedDict()
                for rrole, assoc_clns in six.iteritems(
                        self.assoc_instnames[role][ref_cln]):
                    assoc_clns_dict = OrderedDict()

                    for assoc_cln, inst_names_tup in six.iteritems(assoc_clns):
                        if not inst_names_tup:
                            continue

                        disp_assoc_cln = self.simplify_path(assoc_cln)
                        key = "{}(ResultClass)({} insts)". \
                            format(disp_assoc_cln, len(inst_names_tup))

                        # Build dictionary of associated instance names
                        assoc_clns_dict[key] = OrderedDict()
                        if not summary:
                            # Insts dict is keys only with empty sub-dict
                            # for ascii tree compatibility. i.e. this
                            # is the lowest level in the tree.
                            # Returns OrderedDict
                            inst_names_tup = self.build_inst_names(
                                inst_names_tup,
                                ref_cln,
                                replacements,
                                self.fullpath)

                            assoc_clns_dict[key] = inst_names_tup

                    # Add the role tree element
                    rrole_disp = "{}(ResultRole)".format(rrole)
                    rrole_dict[rrole_disp] = assoc_clns_dict

                # Add the reference class element. Include namespace if
                # different than conn default namespace
                disp_ref_cln = "{}(AssocClass)". \
                    format(self.simplify_path(ref_cln))

                elementstree[disp_ref_cln] = rrole_dict

            # Add the role component to the tree
            disp_role = "{}(Role)".format(role)
            assoctree[disp_role] = elementstree

        # Attach the top of the tree, the source instance path for the
        # shrub.
        display_source_path = self.simplify_path(self.source_path)
        toptree = {display_source_path: assoctree}

        return toptree

    def build_shrub_table(self, output_format, summary):
        """
        Build and return a table representing the shrub. The table
        returned is a string that can be printed to a terminal or or other
        destination.
        """
        def fmt_inst_col(iname_tuples, max_len, summary, ternary):
            """
            Format the instance column display either as a summary count
            or a list of instances possibly with attached integer representing
            reference instance and return it as a single string
            """
            if summary:
                return len(iname_tuples)

            if ternary:
                return "\n".join("{}(refinst:{})".format(
                    self.to_wbem_uri_folded(t[0], max_len=max_len), t[1])
                                 for t in iname_tuples)  # noqa E128

            return "\n".join("{}".format(
                self.to_wbem_uri_folded(t[0], max_len=max_len))
                             for t in iname_tuples)  # noqa E128

        # Display shrub as table
        inst_hdr = "Assoc Inst Count" if summary else "Assoc Inst paths"
        headers = ["Role", "AssocClass", "ResultRole", "ResultClass", inst_hdr]

        # Build the rows of the table
        rows = []
        # assoc_classnames dict struct [role]:[ref_clns]:[rrole]:[assoc_clns]
        for role, ref_clns in six.iteritems(self.instance_shrub):
            for ref_cln in ref_clns:
                is_ternary = self.ternary_ref_classes[ref_cln.classname]
                for rrole, assoc_clns in six.iteritems(
                        self.assoc_instnames[role][ref_cln]):
                    for assoc_cln in assoc_clns:
                        # pylint: disable=line-too-long
                        inst_names = self.assoc_instnames[role][ref_cln][rrole][assoc_cln]  # noqa E501
                        # pylint: enable=line-too-long
                        ml = get_terminal_width() - 65
                        inst_col = fmt_inst_col(inst_names, ml, summary,
                                                is_ternary)

                        rows.append([role,
                                     self.simplify_path(ref_cln),
                                     rrole,
                                     self.simplify_path(assoc_cln),
                                     inst_col])

        title = 'Shrub of {}: {}'.format(self.source_path,
                                         'summary' if summary else 'paths')
        return format_table(rows, headers, title, table_format=output_format)

    def build_assoc_name_tuples(self, assoc_inames, assoc_cln,
                                disp_result_role, role, ref_classname,
                                ref_insts, result_role):
        """
        Build the iname tuples for the instance names defined in assoc_inames
        and add to self.assoc_instnames
        """
        aname_tuples = OrderedDict()
        for aname in assoc_inames:
            for ref_inst_ctr, ref_inst in enumerate(ref_insts):
                if role not in ref_inst:
                    continue
                # If not the reference defined by role,
                # ignore
                if not _match_instname_wo_host(ref_inst.get(role),
                                               self.full_source_path):
                    continue
                # Find other properties with this result_role
                # and create a tuple for each one found.
                # The second data in the tuple identifies the
                # reference instance by its position in the
                # list of reference instances.
                for name in ref_inst.properties:
                    if name.lower() == result_role.lower():
                        pvalue = ref_inst.properties[name].value
                        anamecpy = aname.copy()
                        anamecpy.host = None
                        if pvalue == anamecpy:
                            aname_tuples[aname] = AssocNameTuple(
                                Name=aname,
                                RefInst=ref_inst_ctr)

                        # pylint: disable=line-too-long
                        if disp_result_role not in self.assoc_instnames[role][ref_classname]:  # noqa: E501
                            self.assoc_instnames[role][ref_classname][disp_result_role] = OrderedDict()  # noqa: E501
                        self.assoc_instnames[role][ref_classname][disp_result_role][assoc_cln] = list(aname_tuples.values())  # noqa: E501
                        # pylint: enable=line-too-long

    def to_wbem_uri_folded(self, path, format='standard', max_len=15):
        # pylint: disable=redefined-builtin
        """
        Return the (untyped) WBEM URI string of this CIM instance path.
        This method modifies the pywbem:CIMInstanceName.to_wbem_uri method
        to return a slightly formated string where components are on
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
        # Remove host and namespace if same as source instance
        path = self.simplify_path(path)

        return to_wbem_uri_folded(path, format=format, max_len=max_len)

    def build_inst_names(self, inst_names_tuple, ref_cln, replacements,
                         fullpath=None):
        """
        Build a set of displayable instance names from the inst_names. This
        method tries to simplify the instance names by

        1. Hiding keys that have the same value for all instances. This
           is ignored if there is only a single instance
        2. Hiding certain specific key names that have a common meaning
        throughout the environment including SystemName,
        SystemCreationClassName, and CreationClassName.
        It hides CreationClassName key if the value is the same as the key
        classname.

        Next, if the defining reference class has more than 2 reference
        properties (ternary or greater associations) add an element to the
        instance name display indicate which reference instance is the
        connection for this association instance.

        Finally it removes the host and namespace if they are the same as
        the current host and namespace

        Parameters:

          inst_names_tuple (:func:`~py:collections.namedtuple` object):
            namedtuple containing instancename and integer representing
            reference instance.

          ref_cln (:term:`string`):
             Classname of the reference class.

          replacements (:class:`dicti`):
            No-case dictionary containing the name of each key to be considered
            for replacement with either the value None or a defined value
            for the key.  If the value is None the key will be replaced with
            '~' independent of its value.  If the value is not None, the
            key will be replaced only if value matches the key value.

          fullpath (boolean):
            If True, show the full instance paths.  If not True, build the path
            shortened by modifying selected keys to replace the keys defined
            by the replacements attribute with `~'. In addition all keys
            with the same value are replaced if len(inst_names) is gt 1.

        Returns:
            OrderedDict of modified key names
        """
        assert isinstance(inst_names_tuple, list)
        assert isinstance(inst_names_tuple[0], tuple)
        assert len(inst_names_tuple[0]) == 2
        assert isinstance(replacements, NocaseDict)

        # If path shortening specified, determine which keys can be shortened
        # based on keys with the same value in all instance names
        if not fullpath:
            first_iname = inst_names_tuple[0][0]
            keys_to_hide = {k: True for k in first_iname.keys()}

            # Determine if there are multiple instances with same value
            if len(inst_names_tuple) > 1:
                for iname_tuple in inst_names_tuple:
                    iname = iname_tuple[0]
                    for kbname, kbvalue in iname.items():
                        if kbname not in replacements:
                            if kbvalue != first_iname.keybindings[kbname]:
                                keys_to_hide[kbname] = False
                replacements = {k: None for k, v in keys_to_hide.items() if v}

            # Test for CreationClassName. Hide if same as classname
            ccn = "creationclassname"
            for iname_tuple in inst_names_tuple:
                iname = iname_tuple[0]
                for kbname, kbvalue in iname.keybindings.items():
                    if kbname.lower() == ccn:
                        if iname.keybindings[ccn].lower() == \
                                iname.classname.lower():
                            replacements["CreationClassName"] = None

        ternary = self.ternary_ref_classes[ref_cln.classname]

        modified_inames = OrderedDict()
        for inst_name_tuple in inst_names_tuple:
            iname = self.simplify_path(inst_name_tuple.Name)
            # Convert path to string and possibly shorten
            iname_display = shorten_path_str(iname, replacements, fullpath)

            # If reference class with more than 2 references add indicator
            # to the defining reference instance so the user can match
            # the instances to reference instances.
            if ternary:
                iname_display = '{}(refinst:{})'.format(iname_display,
                                                        inst_name_tuple.RefInst)

            # builds dict with empty value to be ascii_tree compatible
            modified_inames[iname_display] = OrderedDict()
        return modified_inames

    def define_ternary_references(self, ref_insts):
        """
        Build dictionary of reference classes (ternary_ref_classes) in
        conn.References return with Value True if > 2 reference properties
        and False if == 2 reference properties
        """
        for ref_inst in ref_insts:
            count = 0
            if ref_inst.classname not in self.ternary_ref_classes:
                for v in ref_inst.properties.values():
                    if v.type == 'reference':
                        count += 1
                assert count >= 2  # Must return 2 or more reference properties
                # Set value True if count > 2 else False
                self.ternary_ref_classes[ref_inst.classname] = count > 2

    def simplify_path(self, path):
        """
        Simplify the CIMamespace instance defined by path by copying and
        removing the host name and namespace name if they are the same as
        the source instance.  This allows the tree to show only the
        classname for all components of the tree that are in the same
        namespace as the association source instance.

        Parameters:

          path(:class:`~pywbem.CIMInstanceName`):
            Instance name to simplify

        Returns:
          :class:`~pywbem.CIMInstanceName` containing the simplified name

        """
        simple_path = path.copy()
        if simple_path.host and \
                simple_path.host.lower() == self.source_host.lower():
            simple_path.host = None
        if simple_path.namespace and \
                simple_path.namespace.lower() == self.source_namespace.lower():
            simple_path.namespace = None
        return simple_path

    def _get_reference_roles(self, inst_name):
        """
        Internal method to get the list of roles for an association class.
        Uses instance get rather than class get because some
        servers may not support class get operation.

        Parameters:

          inst_name(:class:`~pywbem.CIMInstanceName`):
            instance for which roles will be returned

        Returns:
          List of :term:`string` containg the classnames (roles) contained
          in the defined instance

        """
        try:
            ref_inst = self.conn.GetInstance(inst_name, LocalOnly=False)
        except CIMError as ce:
            click.echo('Exception ref {0}, exception: {1}'.format(inst_name,
                                                                  ce))
            return None
        roles = [pname for pname, pvalue in six.iteritems(ref_inst.properties)
                 if pvalue.type == 'reference']
        if self.verbose:
            print('class {0}, roles {1}'.format(inst_name.classname, roles))
        return roles

    def _get_role_result_roles(self, roles, ref_classname):
        """
        Given the reference classname, separate the role and result_role
        parameters and return them. This method determines that the role
        is the call to ReferenceNames that returns references. Result roles
        are the roles that do not return references. Note that there are
        cases where this basic algorithm returns multiples
        """
        rtn_roles = OrderedDict()
        for tst_role in roles:
            refs = self.conn.ReferenceNames(self.source_path,
                                            Role=tst_role,
                                            ResultClass=ref_classname)
            self.reference_names = refs

            if refs:
                rtn_roles[tst_role] = [r for r in roles if r != tst_role]
        if self.verbose:
            print('ResultRoles: class={0} ResultClass={1} ResultRoles={2}'
                  .format(self.source_path.classname, ref_classname, rtn_roles))
        return rtn_roles
