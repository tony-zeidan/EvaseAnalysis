from collections import defaultdict
from typing import Dict

import networkx as nx

from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.sql_injection.injectionvisitor import InjectionNodeVisitor

import matplotlib.pyplot as plt
from abc import ABC, abstractmethod
import json
import os
from pprint import pprint


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
            print(results)
            if len(results) > 0:
                self.analysis_results['found_any'] = True

                initial_module_struct = m_struct.to_json()
                initial_module_struct['vulnerabilities'] = results
                self.analysis_results['vulnerabilities'].append(initial_module_struct)

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

        print(self.project_root)
        prj_struct = ProjectAnalysisStruct(self.project_name, self.project_root)
        get_mdl_depdigraph(prj_struct)

        if self.sql_injection_detector is not None:
            self.sql_injection_detector.set_project_struct(prj_struct)
            sql_injection_results = self.sql_injection_detector.do_analysis()
            print(sql_injection_results)
            self.analysis_results['sql_injection'] = sql_injection_results

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


def add_node(g, n, groups):
    spl = n.split(".")

    print("ADD", n, groups)


    if len(spl) > 1 and ".".join(spl[:len(spl)-1]) in groups:
        parent = ".".join(spl[:len(spl)-1])

        if not g.has_node(n):
            groups[parent].add(n)
            g.add_node(n, label=n)
        if g.has_node(parent):
            if not g.has_edge(parent, n):
                print("add edge",parent, n)
                g.add_edge(parent, n)
    else:
        if not g.has_node(n):
            groups[n] = set()
            g.add_node(n, label=n)


def get_mdl_depgraphabs(prj: ProjectAnalysisStruct) -> Dict:
    depgraph = {}
    for k, v in prj.get_module_structure().items():
        depgraph[k] = set()
        for _, (mdl_name, _) in v.get_module_imports().items():
            depgraph[k].add(mdl_name)

        for _, (mdl_name, _) in v.get_local_imports().items():
            depgraph[k].add(mdl_name)

    print("DEPGRAPH")
    pprint(depgraph)


def get_mdl_depdigraph(prj: ProjectAnalysisStruct):
    graph_info = get_mdl_depgraph(prj)

    colors = ['red', 'green', 'blue', 'purple']

    graph = nx.DiGraph(name="Generated dependency graph")

    groups = {}
    for uses, defs_dct in graph_info.items():
        add_node(graph, uses, groups)
        for defs, defs_props in defs_dct.items():
            add_node(graph, defs, groups)

            if len(defs_props) == 0:
                if not graph.has_edge(uses, defs):
                    graph.add_edge(uses, defs)
            else:
                for def_prop in defs_props:
                    namer = f'{defs}.{def_prop}'
                    add_node(graph, namer, groups)

                    print("NAMER", namer)

                    if not graph.has_edge(uses, namer):
                        graph.add_edge(uses, namer)

    print("HERE", graph.has_edge("backend.vul", "backend.vul.get_user_from_db"))
    nx.draw(graph, node_size=800, with_labels=True,
            bbox=dict(facecolor="skyblue", edgecolor='black', boxstyle='round,pad=0.4'), connectionstyle="arc3,rad=0.1")
    plt.show()
    plt.savefig('depgraph', dpi='figure', format=None, metadata=None,
                bbox_inches=None, pad_inches=0.1,
                facecolor='auto', edgecolor='auto',
                backend=None
                )
    return graph


if __name__ == '__main__':
    apr = AnalysisPerformer("demo", r"C:\courses\SYSC_4907\EvaseAnalysis\tests\resources\demo")
    apr.perform_analysis()
