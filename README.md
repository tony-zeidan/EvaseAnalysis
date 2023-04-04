[![CI Tests](https://github.com/tony-zeidan/EvaseAnalysis/actions/workflows/ci_tests.yml/badge.svg)](https://github.com/tony-zeidan/EvaseAnalysis/actions/workflows/ci_tests.yml)

# Evase Analysis Library
This library intends to help users detect SQL Injection vulnerabilities from their source code. 
It has several structures that take-in Python source code and use abstract-syntax trees (ASTs) to analyze for such vulnerabilities.
The code was initially part of a much bigger project, but as to provide separation of concerns, the functionality
for detecting the SQL injection-related vulnerabilities was separated out into this package.

## What's New

In the latest version of the library:
- The performance of the code has been slightly improved by the removal of creating unnecessary expensive `NodeVisitor` and `NodeTransformer` objects.
  - Instead, the objects are created as a single instance and have their states reset.
- Most classes in the system now use `@property` annotations for getters and setters now.
- The `ProjectAnalysisStruct` class can now be queried for module structures like a dictionary.
  - By passing the name of the module, you can retrieve the corresponding `ModuleAnalysisStruct`.
- The functions are able to fail more gracefully when encountering unexpected AST nodes.
- The Breadth-First search functions keep track of paths traversed.
  - The main traversal function (`traversal_from_exec`) now outputs a mapping of ending nodes to their possible paths.
- The dependency graph generated by `ProjectAnalysisStruct` has been tested for many use cases and seems to work very well.
- Some bugs in the module imports generated by `ModuleImportResolver` have been fixed.
  - The resolver now better handles variant imports like:
    - `from <one or more (.)> import <function|module|*>`
    - If we can backtrack to a module (through the count of '.' characters) we assume the object being imported is a module, otherwise it is a function.
- The graph node grouping mechanism in `AnalysisPerformer` has had some bugs resolved.
- Nodes in the graph now appear with the form `<package style name>:<function name>` for functions found WITHIN the analysis of the code (not external libraries).

## Issues

There are still a variety of issues with the handling of the various errors that our traversal mechanisms encounter.
- Those `Flask` endpoints that do not accept function parameters, (POST-type requests) aren't considered vulnerable due to inadequacies with the `collect_vulnerable_vars` function.
- There are many ways of writing imports, and it is likely that the `ModuleImportResolver` doesn't consider all of these.

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

## Important Information

The code made in this package relies on various functions applied to Abstract Syntax Trees (ASTs).

Many of the functions in the code are required to perform other functions.
The functions directly relating to ASTs at a low level require that the input ASTs be modified. 
The functions inside of input ASTs must have their scopes resolved. 
```python
# example.py

def foo():
  print("FOO")
  
class Bar:
  
  def foo(self):
    print("FOO")
```
In this example, the AST output would look something like:
```
<FunctionDef name='foo'>
<ClassDef name='Bar'>
  <FunctionDef name='foo'>
```
As you can see, while traversing using a `NodeVisitor` it would be difficult to determine the scope of the inner
function.
As such we created the `ScopeResolver` such that the output AST would look something like:
```
<FunctionDef name='foo'>
<ClassDef name='Bar'>
  <FunctionDef name='Bar.foo'>
```

For functions involving the analysis of dependencies, the import nodes inside of input ASTs must also have their
`module` attribute be absolute rather than relative. The importable items from the imported module must also be directly
specified if an import in the form of `<from | import> ... *` is being used. Take the following script for example:

```python
# package/imported.py
def foo():
  print("FOO")
  
def bar():
  print("BAR")
  
class Bar:
  
  def bar(self):
    print("BAR")

# package/inner/example.py

from ..imported import *
```
Imports in this form are very hard to analyze because ASTs don't provide any information other than the form of the
import. The AST for `package/inner/example.py` would look something like:
```
<Import module=None names="*">
```
It's clear that this doesn't help much when analyzing dependencies. For this reason we created the `SurfaceLevelVisitor`
and `ModuleImportResolver` that work in tandem.
The `SurfaceLevelVisitor` collects all the surface level importable items from a module. We then combine these
into a list and make an instance of `ModuleImportResolver` that resolves module names in import nodes and their imported
items. Using these two instances properly retrieves the following AST.
```
<Import module="package.imported" names=["foo", "bar", "Bar"]>
```

Most of the classes within this library rely on the fact that the scopes will be resolved, and that the imports are
correctly resolved.

## Installation
This package is available on PyPI! You can install it using:
```
pip install evase-analysis
```

Or you can simply clone the repository and run:

```
pip install .
```
(in the directory with `pyproject.toml`)

