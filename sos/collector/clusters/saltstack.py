# Copyright Red Hat 2022, Trevor Benson <trevor.benson@gmail.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import json
from shlex import quote
from sos.collector.clusters import Cluster


class saltstack(Cluster):
    """
    The saltstack cluster profile is intended to be used on saltstack
    clusters (Salt Project).
    """

    cluster_name = "Saltstack"
    packages = ("salt-master",)
    sos_plugins = ["saltmaster"]
    cmd = "salt-run --out=pprint manage.up"
    hostname_cmd = "salt --out=newline_values_only {minion} grains.get fqdn"
    strict_node_list = True
    option_list = [
        ("all_nodes", False, "Filter node list to all nodes, even if "
         " salt-mionion service is down."),
        ("compound", "", "Filter node list to those matching compound"),
        ("glob", "", "Filter node list to those matching glob pattern"),
        ("grain", "", "Filter node list to those with matching grain"),
        ("hostnames", False, "When minion isn't resolvable for control_persist"
         " this will return the fqdn of the minion. This option is not"
         " compatible with option all_nodes or transport saltstack"),
        ("list", "", "Filter node list to those matching list"),
        ("nodegroup", "", "Filter node list to those matching nodegroup"),
        ("pillar", "", "Filter node list to those with matching pillar"),
        ("regex", "", "Filter node list to those matching regex"),
        ("subnet", "", "Filter node list to those in subnet"),
    ]
    targeted = False

    def _get_up_nodes(self) -> list:
        res = self.exec_primary_cmd(self.cmd)
        if res["status"] != 0:
            raise Exception("Node enumeration did not return usable output")
        if not self.get_option("hostnames"):
            return json.loads(res["output"].replace("'", '"'))
        hostnames = []
        minions = json.loads(res["output"].replace("'", '"'))
        for minion in minions:
            hostname_cmd = self.hostname_cmd.format(minion=minion)
            hostnames.append(
                self.exec_primary_cmd(
                    hostname_cmd
                )["output"].strip()
            )
        return hostnames

    def _get_all_nodes(self) -> list:
        nodes = []
        res = self.exec_primary_cmd(self.cmd)
        if res["status"] != 0:
            raise Exception("Node enumeration did not return usable output")
        salt_json_output = json.loads(res["output"].replace("'", '"'))
        for _, value in salt_json_output.items():
            nodes.extend(value)
        if self.get_option("hostnames"):
            print("Hostname option not implemented for all_nodes, ignoring.")
        return nodes

    def get_nodes(self):
        # Default to all online nodes
        if self.get_option("all_nodes"):
            self.cmd = "salt-run --out=pprint manage.status'"
            return self._get_all_nodes()
        elif self.get_option("compound"):
            self.cmd += (f" tgt={quote(self.get_option('compound'))}"
                         " tgt_type=compound")
        elif self.get_option("glob"):
            self.cmd += (f" tgt={quote(self.get_option('glob'))}"
                         " tgt_type=glob")
        elif self.get_option("grain"):
            self.cmd += (f" tgt={quote(self.get_option('grain'))}"
                         " tgt_type=grain")
        elif self.get_option("list"):
            self.cmd += (f" tgt={quote(self.get_option('list'))}"
                         " tgt_type=list")
        elif self.get_option("nodegroup"):
            self.cmd += (f" tgt={quote(self.get_option('nodegroup'))}"
                         " tgt_type=nodegroup")
        elif self.get_option("pillar"):
            self.cmd += (f" tgt={quote(self.get_option('pillar'))}"
                         " tgt_type=pillar")
        elif self.get_option("regex"):
            self.cmd += (f" tgt={quote(self.get_option('regex'))}"
                         " tgt_type=regex")
        elif self.get_option("subnet"):
            self.cmd += (f" tgt={quote(self.get_option('subnet'))}"
                         " tgt_type=subnet")

        return self._get_up_nodes()


# vim: set et ts=4 sw=4 :
