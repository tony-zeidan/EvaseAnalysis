from evase.structures.projectstructure import ProjectAnalysisStruct
from evase.sql_injection.injectionvisitor import InjectionNodeVisitor

from abc import ABC, abstractmethod
import json
import os


class BehaviourAnalyzer(ABC):

    def __init__(
            self,
            project_struct: ProjectAnalysisStruct = None,
            executor=None
    ):
        self.project_struct = project_struct
        self.analysis_results = dict(vulnerabilities={}, found_any=False)
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
                self.analysis_results['vulnerabilities'][m_name] = results

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
