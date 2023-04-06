from typing import Union, Generator
from pathlib import Path

from evase.exceptions.exceptions import EvasePathException


def check_path(path: Union[str, Path], file_ok: bool = False, file_req: bool = False, absolute_req: bool = False,
               ret_absolute: bool = True, notexists_ok: bool = False) -> Path:
    """
    Check the path for common issues.
    Raises exceptions based on criteria.
    Returns the path if everything succeeds.


    :param path: The path
    :param file_ok: Whether the path can be a file
    :param absolute_req: Whether the path has to be absolute or not
    :param ret_absolute: Whether to return the path as absolute or not
    """

    path = Path(path)
    if not path.exists() and not notexists_ok:
        raise EvasePathException(path, "Evase can't process a code repository that doesn't exist on the file system.")
    elif not path.is_dir() and not file_ok and not notexists_ok:
        raise EvasePathException(path, "Evase can't be passed a single file to analyze, it requires a project folder.")
    elif not path.is_file() and file_req and not notexists_ok:
        raise EvasePathException(path, "Evase requires a file for this operation.")
    elif not path.is_absolute() and absolute_req and not notexists_ok:
        raise EvasePathException(path, "Evase requires an absolute path for this operation.")

    if ret_absolute:
        return path.absolute()
    else:
        return path


def get_package_name(file: Union[str, Path], root: Union[str, Path]):
    """
    Obtain the package-style name of a python module.

    :param file: The name of the file
    :param root: The root of the project
    :return: The package name of the module
    """

    file = check_path(file, file_ok=True, absolute_req=False, ret_absolute=True)
    root = check_path(root, file_ok=False, absolute_req=False, ret_absolute=True)

    if file.is_relative_to(root):
        names = []
        curr_dir = Path(file.parent)

        while True:
            if not curr_dir.is_relative_to(root):
                break

            init_file = Path(curr_dir, "__init__.py")
            if init_file.exists():
                names.insert(0, str(curr_dir.name))
                curr_dir = curr_dir.parent
            else:
                break

        names.append(str(file.name).replace(".py", ""))
        return ".".join(names)
    else:
        raise EvasePathException(file, "File given is not relative to the root!")


def get_project_module_names(root: Union[str, Path]) -> Generator:
    """
    Retrieve the package-style names for all the files in a project.

    :param root: The root directory of the project
    :return: A lazy generator for each package-style name, path pair
    """
    root = check_path(root, file_ok=False, absolute_req=False, ret_absolute=True)

    all_files = root.rglob("*.py")
    for file in all_files:
        yield get_package_name(file, root), file
