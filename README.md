[![CI Backend Tests](https://github.com/Bruce-liushaopeng/Evase/actions/workflows/ci_tests.yml/badge.svg?branch=main)](https://github.com/Bruce-liushaopeng/Evase/actions/workflows/ci_tests.yml)

# Evase Analysis Library
This library intends to help users detect SQL Injection vulnerabilities from their source code. 
It has several structures that take-in Python source code and use abstract-syntax trees (ASTs) to analyze for such vulnerabilities.
The code was initially part of a much bigger project, but as to provide separation of concerns, the functionality
for detecting the SQL injection-related vulnerabilities was separated out into this package.

## Usage
This package was developed initially with the intention that it be used in the Backend for the Evase web-application,
so it is structured as such. To use it in a program, the user first needs to specify information pertaining to the project.


The user is able to analyze the project with an instance of the `AnalysisPerformer` class. 

```python
from evase.structures.analysisperformer import AnalysisPerformer

code_analyzer = AnalysisPerformer(
    project_name="myProject",
    project_root="<filepath to root>"
)

code_analyzer.perform_analysis()

print(code_analyzer.get_results())

# optionally, output to JSON
code_analyzer.results_to_JSON("<output directory>")
```

Behind the scenes, this instance is performing multiple traversals of the abstract syntax trees (ASTs) generated from
the source code in the project.

## Installation
The package will be installable via PyPI. For now clone the repository, and run the following command:

`pip install .`

