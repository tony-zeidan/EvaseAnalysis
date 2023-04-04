import ast
from typing import Set


class SurfaceLevelVisitor(ast.NodeVisitor):
    def __init__(self):
        """
        A traverser that finds surface level importable items from the current AST.
        """
        self._surface_names = set()

    def generic_visit(self, node):
        """
        Traverse over any node.

        :param node: The node to visit
        """
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            return

        if isinstance(node, ast.Module):
            super().generic_visit(node)

        # possibly importable
        elif isinstance(node, ast.Assign):
            # only one assignment
            if hasattr(node.targets[0], 'id'):
                for val in node.targets:
                    self.surface_names.add(val.id)
            # multiple assignments
            else:
                for val in node.targets[0].elts:
                    self.surface_names.add(val.id)
        else:
            if hasattr(node, 'name'):
                self.surface_names.add(node.name)

    @property
    def surface_names(self) -> Set[str]:
        """
        Retrieve the surface names found during traversal.

        :return: Surface importable names
        """
        return self._surface_names

    def reset(self):
        """
        Reset the state of the visitor.
        """
        self._surface_names.clear()
