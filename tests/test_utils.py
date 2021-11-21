import pathlib


def resolve_test_data_directory_path() -> pathlib.PurePath:
    current_file = pathlib.Path(__file__).resolve()
    project_root = current_file.parent.parent
    return project_root / "test_data"
