from typing import Dict

import networkx as nx

from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.sql_injection.injectionvisitor import InjectionNodeVisitor

from abc import ABC, abstractmethod
import json
import os
from pprint import pprint

attack_vector_edge_setting = {
    'color': 'red',
    'weight': 2
}

attack_vector_node_setting = {
    'color': {
        'background': 'red',
        'border': "#FFCCCB",
        'highlight': {
            'background': 'red',
            'border': "#FFCCCB",
        }
    },
}

package_edge_setting = {
    'dashes': True,
    'color': {
        'inherit': False
    },
    'arrows': {
        'to': {
            'enabled': True,
            'type': 'bar',
            'scaleFactor': 0.5
        },
        'from': {
            'enabled': True,
            'type': 'bar',
            'scaleFactor': 0.5
        }
    }
}

class BehaviourAnalyzer(ABC):

    def __init__(
            self,
            project_struct: ProjectAnalysisStruct = None,
            executor=None
    ):
        self.project_struct = project_struct
        self.analysis_results = dict(vulnerabilities=[], found_any=False)
        self.executor = executor

    def get_project_struct(self):
        return self.project_struct

    def get_analysis_results(self):
        return self.analysis_results

    def set_project_struct(self, project_struct: ProjectAnalysisStruct):
        self.project_struct = project_struct

    def set_executor(self, executor):
        self.executor = executor

    @abstractmethod
    def do_analysis(self):
        if self.project_struct is None:
            raise ValueError("Project structure needs to be set before performing analysis.")
        if self.executor is None:
            raise ValueError("An executor function needs to be set before performing analysis.")
        pass


class SQLInjectionBehaviourAnalyzer(BehaviourAnalyzer):

    def __init__(self, project_struct: ProjectAnalysisStruct = None):
        super().__init__(project_struct)

    def do_analysis(self):
        for m_name, m_struct in self.project_struct.get_module_structure().items():
            visitor = InjectionNodeVisitor(self.project_struct, m_name)
            visitor.visit(m_struct.get_ast())
            results = visitor.get_vulnerable_funcs()
            if len(results) > 0:
                self.analysis_results['found_any'] = True
                self.analysis_results['graph'] = results

        return self.analysis_results


class AnalysisPerformer:

    def __init__(
            self,
            project_name: str = None,
            project_root: str = None):
        """
        Analyzes the code given for SQL injection vulnerabilities.
        This class is a wrapper for evase tools provided in this package.

        :param project_name: The name of the project
        :param project_root: The root directory of the project
        """

        self.project_name = project_name
        self.project_root = project_root
        self.analysis_results = {}

        self.sql_injection_detector = SQLInjectionBehaviourAnalyzer()

    def perform_analysis(self):
        """
        Performs analysis on the code structure that is currently loaded.
        Results are stored in the analysis_results field.
        """

        prj_struct = ProjectAnalysisStruct(self.project_name, self.project_root)
        graph, groups = get_mdl_depdigraph(prj_struct)


        if self.sql_injection_detector is not None:
            pprint(prj_struct.get_module_structure())
            self.sql_injection_detector.set_project_struct(prj_struct)
            sql_injection_results = self.sql_injection_detector.do_analysis()
            graph, groups = extend_depgraph_attackvectors(graph, groups, sql_injection_results)
            graph_data = nx.node_link_data(graph, source='from', target='to', link='edges')

            # pprint(x)
            #nt = Network(directed=True, select_menu=True)
            #nt.from_nx(graph)

            # nx.set_edge_attributes(graph, ']-', name='arrowstyle')
            # nx.draw_networkx(graph, arrowstyle='<|-')
            # plt.show()

            #nt.toggle_physics(True)
            # print(nt.generate_html("ex.html"))

            # nt.set_options('{"edges": {"dashes": true}}')
            #nt.show("nx.html", notebook=False)

            self.analysis_results['graph'] = {}
            self.analysis_results['graph']['total'] = graph_data
            sql_results_dct = {}
            for k, v in sql_injection_results['graph'].items():
                sql_results_dct[k] = nx.node_link_data(v, source='from', target='to', link='edges')

            self.analysis_results['graph']['vectors'] = sql_results_dct

            pprint(self.analysis_results)

            # self.analysis_results['analysis'] = sql_injection_results
            # pprint(self.analysis_results)

    def get_results(self):
        """
        Retrieves the results of analysis.

        :return: Results in the form of a dictionary
        """
        return self.analysis_results

    def results_to_JSON(self, filepath: str) -> str:
        """
        Outputs the current results to a JSON path.
        The output is a file in the directory specified in the form of <project_name>-analysis-results.json.

        :param filepath: The path to the directory
        :return: The JSON formatted string
        """
        jform = json.dumps(self.analysis_results, indent=4)
        if not os.path.exists(filepath) or not os.path.isdir(filepath):
            raise ValueError("Path doesn't exist or it isn't a directory")
        fpath = os.path.join(filepath, f'{self.project_name}-analysis-results.json')
        with open(fpath, 'w') as f:
            f.write(jform)
        return jform


def get_mdl_depgraph(prj: ProjectAnalysisStruct) -> Dict:
    depgraph = {}
    for k, v in prj.get_module_structure().items():
        depgraph[k] = {}
        for aname, (mdl_name, fn_name) in v.get_module_imports().items():

            if mdl_name not in depgraph[k]:
                depgraph[k][mdl_name] = []

            if fn_name == aname:
                continue

            elif fn_name is None:
                depgraph[k][mdl_name].append(aname)

            else:
                if fn_name not in depgraph[k][mdl_name]:
                    depgraph[k][mdl_name].append(fn_name)

        for fn_name, (mdl_name, _) in v.get_local_imports().items():

            namer = f'{k}.{fn_name}'
            if namer not in depgraph:
                depgraph[namer] = []

            depgraph[namer].append(mdl_name)

    print("DEPGRAPH")
    pprint(depgraph)
    return depgraph


def add_node(g, n, groups, edge_settings: dict = None, node_settings: dict = None):
    if edge_settings is None:
        edge_settings = {}
    if node_settings is None:
        node_settings = {}

    spl = n.split(".")

    if len(spl) > 1 and ".".join(spl[:len(spl) - 1]) in groups:
        parent = ".".join(spl[:len(spl) - 1])

        if not g.has_node(n):
            groups[parent].add(n)
            g.add_node(n, label=n, **node_settings)
        if g.has_node(parent):
            if not g.has_edge(n, parent):
                g.add_edge(n, parent, **edge_settings)
    else:
        if not g.has_node(n):
            groups[n] = set()
            g.add_node(n, label=n, **node_settings)


def get_mdl_depgraphabs(prj: ProjectAnalysisStruct) -> Dict:
    depgraph = {}
    for k, v in prj.get_module_structure().items():
        depgraph[k] = set()
        for _, (mdl_name, _) in v.get_module_imports().items():
            depgraph[k].add(mdl_name)

        for _, (mdl_name, _) in v.get_local_imports().items():
            depgraph[k].add(mdl_name)

    # print("DEPGRAPH")
    # pprint(depgraph)


def trim_depdigraph(graph: nx.DiGraph, groups):
    # Trim unnecessary groups
    toparent = []
    for group, members in groups.items():

        if len(members) == 1:
            mem = members.pop()
            ineds = list(graph.in_edges(mem))
            outeds = list(graph.out_edges(mem))

            for ined in ineds:
                graph.remove_edge(*ined)
            for outed in outeds:
                graph.remove_edge(*outed)

            # remove the parent
            graph.remove_node(group)

            for ined in ineds:
                if ined[0] != group:
                    graph.add_edge(*ined)

            for outed in outeds:
                if outed[1] != group:
                    graph.add_edge(*outed)

            toparent.append(mem)
    groups.update({k: set() for k in toparent})


def get_mdl_depdigraph(prj: ProjectAnalysisStruct):
    graph_info = get_mdl_depgraph(prj)
    graph = nx.DiGraph()

    groups = {}
    for uses, defs_dct in graph_info.items():
        add_node(graph, uses, groups)
        for defs, defs_props in defs_dct.items():
            add_node(graph, defs, groups, edge_settings=dict(dashes=True, arrowstyle=']-', arrows=dict(
                to=dict(enabled=True, type="bar", scaleFactor=0.5))))

            if len(defs_props) == 0:
                if not graph.has_edge(uses, defs):
                    graph.add_edge(uses, defs, edge_settings=dict(dashes=True, arrowstyle=']-', arrows=dict(
                        to=dict(enabled=True, type="bar", scaleFactor=0.5))))
            else:
                for def_prop in defs_props:
                    namer = f'{defs}.{def_prop}'
                    add_node(graph, namer, groups, edge_settings=dict(dashes=True, arrowstyle=']-', arrows=dict(
                        to=dict(enabled=True, type="bar", scaleFactor=0.5))))

                    if not graph.has_edge(uses, namer):
                        graph.add_edge(uses, namer)

    trim_depdigraph(graph, groups)


    return graph, groups


def extend_depgraph_attackvectors(graph: nx.DiGraph, groups: Dict, analysis: Dict):
    # def helper(d: Dict):
    #    for k, v in dict

    res = analysis
    if res['found_any']:
        res = res['graph']

        for vul_mdl, attack_graph in res.items():
            for edge in attack_graph.edges:
                add_node(graph, edge[0], groups, edge_settings=package_edge_setting, node_settings=attack_vector_node_setting)
                add_node(graph, edge[1], groups, edge_settings=package_edge_setting, node_settings=attack_vector_node_setting)

                # safety, only add the edge if it isn't there
                if not graph.has_edge(edge[1], edge[0]):
                    graph.add_edge(edge[1], edge[0], **attack_vector_edge_setting)

        trim_depdigraph(graph, groups)

    return graph, groups


if __name__ == '__main__':
    apr = AnalysisPerformer("demo", r"U:\courses\SYSC_4907\EvaseAnalysis\tests\resources\demo")
    apr.perform_analysis()
