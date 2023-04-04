import ast
import unittest
import tests.testutil as testutil
import copy

from evase.depanalyze.scoperesolver import ScopeResolver


class TestScopeResolver(unittest.TestCase):
    """
    Unit tests for scope resolver functionality.
    """

    def setUp(self):
        """
        Setup with AST.
        """
        self.test_file1 = testutil.get_ast_from_filename(testutil.scres1_filename)

    def test_resolverobj(self):
        """
        Test the ability of the scope resolver to accurately resolve the scopes of functions in an AST.=
        """

        classdefs = []
        belongs = []
        funcdefs = []

        for node in ast.walk(self.test_file1):
            if isinstance(node, ast.ClassDef):
                classdefs.append(node)
            elif isinstance(node, ast.FunctionDef):
                nodecpy = copy.deepcopy(node)
                funcdefs.append(node)
                found = False
                for cls in classdefs:
                    for subnode in ast.walk(cls):
                        if subnode == node:
                            found = True
                            belongs.append((cls, nodecpy))
                            break

                if not found:
                    belongs.append((None, nodecpy))

        self.test_file1 = ScopeResolver().visit(self.test_file1)
        print(ast.dump(self.test_file1))

        for node, (cls, fn) in zip(funcdefs, belongs):
            shname = f'{cls.name}:{fn.name}' if cls else fn.name
            self.assertEqual(shname, node.name, "Node name wasn't formatted properly")
