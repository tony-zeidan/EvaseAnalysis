from typing import Dict, Tuple, List, Set

import networkx as nx
from networkx import DiGraph

from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.sql_injection.injectionvisitor import InjectionNodeVisitor

from abc import ABC, abstractmethod
import json
import os
from pprint import pprint

import matplotlib.pyplot as plt

attack_vector_edge_setting = {
    'vulnerable': True,
    'color': 'red',
    'arrows': {
        'to': {
            'enabled': True
        },
    },
    'weight': 2
}

attack_vector_node_setting = {
    'vulnerable': True,
    'color': {
        'background': 'red',
        'border': "#FFCCCB",
        'highlight': {
            'background': 'red',
            'border': "#FFCCCB",
        }
    },
}

uses_node_setting = {
    'vulnerable': False,
}

uses_edge_setting = {
    'vulnerable': False,
    'arrows': {
        'to': {
            'enabled': True
        },
    }
}

package_edge_setting = {
    'vulnerable': False,
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
        """
        An abstract class of an analyzer that detects specific attack behaviours within a project.

        :param project_struct: The project structure to analyze
        :param executor: The execution function to run for analysis
        """

        self.project_struct = project_struct
        self.analysis_results = dict(vulnerabilities=[], found_any=False)
        self.executor = executor

    def get_project_struct(self) -> ProjectAnalysisStruct:
        """
        Retrieve the project analysis structure.

        :return: The analysis structure being analyzed
        """
        return self.project_struct

    def get_analysis_results(self) -> Dict:
        """
        Retrieve the analysis result of the analyzer.

        :return: The mapping of analysis results
        """

        return self.analysis_results

    def set_project_struct(self, project_struct: ProjectAnalysisStruct):
        """
        Set the project structure to analyze.

        :param project_struct: The project structure to analyze
        """

        self.project_struct = project_struct

    def set_executor(self, executor):
        """
        Set the executor function of this analyzer.

        :param executor: The executor function.
        """
        self.executor = executor

    @abstractmethod
    def do_analysis(self):
        """
        Abstract method to do the analysis and output a result.
        """

        if self.project_struct is None:
            raise ValueError("Project structure needs to be set before performing analysis.")
        if self.executor is None:
            raise ValueError("An executor function needs to be set before performing analysis.")
        pass


class SQLInjectionBehaviourAnalyzer(BehaviourAnalyzer):

    def __init__(self, project_struct: ProjectAnalysisStruct = None):
        """
        An SQL injection analyzer that identifies such vulnerabilities in the project structure.

        :param project_struct: The project structure to analyze
        """
        super().__init__(project_struct)

    def do_analysis(self) -> Dict:
        """
        Perform the SQL injection analysis and output the result.

        :return: A dictionary of the analysis results
        """
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
            #pprint(prj_struct.get_module_structure())
            self.sql_injection_detector.set_project_struct(prj_struct)
            sql_injection_results = self.sql_injection_detector.do_analysis()

            graph, groups = extend_depgraph_attackvectors(graph, groups, sql_injection_results['graph'])
            graph_data = nx.node_link_data(graph, source='from', target='to', link='edges')

            self.analysis_results['graph'] = {}
            self.analysis_results['graph']['total'] = graph_data
            sql_results_dct = {}
            # for k, v in sql_injection_results['graph'].items():
            #    sql_results_dct[k] = nx.node_link_data(v, source='from', target='to', link='edges')

            # self.analysis_results['graph']['vectors'] = sql_results_dct

            #pprint(self.analysis_results)

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
        pprint(self.analysis_results)
        jform = json.dumps(self.analysis_results, indent=4)
        if not os.path.exists(filepath) or not os.path.isdir(filepath):
            raise ValueError("Path doesn't exist or it isn't a directory")
        fpath = os.path.join(filepath, f'{self.project_name}-analysis-results.json')
        with open(fpath, 'w') as f:
            f.write(jform)
        return jform


def add_node(g: nx.DiGraph, n: str, groups: Dict[str, Set[str]], edge_settings: Dict = None, node_settings: Dict = None):
    """
    Add a node to the dependency graph.
    If the node already exists, update the properties of the node.
    If the node doesn't exist, create a new node.
    If the node belongs to a package group, add an edge between the package parent and the new node.

    :param g: The dependency graph
    :param n: The new node to add to the graph
    :param groups: The groups of packages to modules in the package
    :param edge_settings: If an edge is to be added, the settings for that edge
    :param node_settings: If a node is to be added, the settings for that node
    :return: None
    """

    if edge_settings is None:
        edge_settings = {}
    if node_settings is None:
        node_settings = {}

    spl = n.split(".")

    if len(spl) > 1:
        parent = ".".join(spl[:len(spl) - 1])
        if parent in groups:

            if parent == "backend.app":
                print("PARENT OF", n)
                print(groups[parent])

            if not g.has_node(n):
                groups[parent].add(n)
                print(groups[parent])
                g.add_node(n, label=n, **node_settings)
            else:
                if n not in groups[parent]:
                    groups[parent].add(n)

                nx.set_node_attributes(g, {n: node_settings})

            if g.has_node(parent):
                if not g.has_edge(n, parent):
                    g.add_edge(n, parent, **edge_settings)
        else:
            if not g.has_node(n):
                if parent == "backend.app":
                    print("RESET APP")

                groups[n] = set()
                g.add_node(n, label=n, **node_settings)

    return groups


def trim_depdigraph(graph: nx.DiGraph, groups: Dict[str, Set[str]], edge_settings: Dict = None):
    """
    Trim NetworkX dependency graph representation by getting rid of groups that only
    have one element present.

    :param graph: The graph to trim groups from
    :param groups: The grouping of modules within the graph (package name to nodes in that package)
    :param edge_settings: The settings of edges when re-adding the edges back
    :return: None
    """

    if edge_settings is None:
        edge_settings = {}

    # Trim unnecessary groups
    remparent = []
    toparent = []
    for group, members in groups.items():

        if len(members) == 0:
            print("ZERO MEMBERS", group, len(graph.out_edges(group)), len(graph.in_edges(group)))

            if graph.has_node(group) and len(graph.in_edges(group)) == 0 and len(graph.out_edges(group)) == 0:
                graph.remove_node(group)
                remparent.append(group)

        elif len(members) == 1:

            if graph.has_node(group) and len(graph.out_edges) == 1:
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
                        graph.add_edge(*ined, **edge_settings)

                for outed in outeds:
                    if outed[1] != group:
                        graph.add_edge(*outed, **edge_settings)

                remparent.append(group)
                toparent.append(mem)
                print(groups)

    for par in remparent:
        del groups[par]

    groups.update({k: set() for k in toparent})
    return groups


def get_mdl_depdigraph(prj: ProjectAnalysisStruct) -> Tuple[DiGraph, Dict[str, Set[str]]]:
    """
    Turn the module dependency graph into a NetworkX graph.

    :param prj: The project analysis structure containing the static dependency graph
    :return: The NetworkX graph object and a mapping between modules under similar package names
    """

    graph_info = prj.get_static_depgraph()
    graph = nx.DiGraph()

    groups = {}
    for uses, defs_dct in graph_info.items():
        groups = add_node(graph, uses, groups, node_settings=uses_node_setting, edge_settings=package_edge_setting)

        for defs, defs_props in defs_dct.items():
            groups = add_node(graph, defs, groups, node_settings=uses_node_setting, edge_settings=package_edge_setting)

            if len(defs_props) == 0:
                if not graph.has_edge(uses, defs):
                    graph.add_edge(uses, defs, **uses_edge_setting)
            else:
                for def_prop in defs_props:
                    namer = f'{defs}.{def_prop}'
                    groups = add_node(graph, namer, groups, node_settings=uses_node_setting, edge_settings=package_edge_setting)

                    if not graph.has_edge(uses, namer):
                        graph.add_edge(uses, namer, **uses_edge_setting)


    groups = trim_depdigraph(graph, groups, edge_settings=uses_edge_setting)

    return graph, groups


def extend_depgraph_attackvectors(graph: nx.DiGraph, groups: Dict[str, Set[str]], analysis: Dict[str, nx.DiGraph]) -> Tuple[DiGraph, Dict[str, Set[str]]]:
    """
    Extend the main dependency NetworkX graph with the subgraphs for each individual
    vulnerability.

    Basic Idea:
    - Go through each vulnerability graph found during the analysis and add
    all nodes and edges from these subgraphs to the main graph
    - Copy the vulnerability graphs to the main graph

    :param graph: The main dependency graph
    :param groups: Groups in the graph (similar modules together)
    :param analysis: The analysis results of the program, keys are modules and values are the NetworkX graphs
    :return: The extended graph and new groupings
    """

    # loop over each vulnerability in each module
    for vul_mdl, attack_graph in analysis.items():

        # loop over attack vector edges (each individual vulnerability graph)
        for ed1, ed2 in attack_graph.edges:

            # ed1 is the first node in the edge, and ed2 is the second (from->to)

            # TODO: get attributes of the current node and add them to the attack vector setting

            new_attack_vector_node_setting1 = attack_vector_node_setting.copy()
            new_attack_vector_node_setting2 = attack_vector_node_setting.copy()

            groups = add_node(graph, ed1, groups, edge_settings=package_edge_setting,
                     node_settings=new_attack_vector_node_setting1)
            groups = add_node(graph, ed2, groups, edge_settings=package_edge_setting,
                     node_settings=new_attack_vector_node_setting2)

            # safety, only add the edge if it isn't there
            if not graph.has_edge(ed2, ed1):
                graph.add_edge(ed2, ed1, **attack_vector_edge_setting)

    # for safety, trim the graph after; don't worry about this
    groups = trim_depdigraph(graph, groups, edge_settings=uses_edge_setting)

    return graph, groups



