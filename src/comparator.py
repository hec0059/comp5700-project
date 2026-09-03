"""Task 2: Compare KDE YAML outputs from Task 1."""

from pathlib import Path
import re

import yaml


NO_NAME_DIFFERENCES = (
    "NO DIFFERENCES IN REGARDS TO ELEMENT NAMES"
)

NO_REQUIREMENT_DIFFERENCES = (
    "NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS"
)


def load_yaml_inputs(
    yaml_file1: str | Path,
    yaml_file2: str | Path,
) -> tuple[dict, dict]:
    """
    Load and validate two Task 1 KDE YAML files.
    """

    paths = (
        Path(yaml_file1),
        Path(yaml_file2),
    )

    loaded = []

    for path in paths:
        if not path.exists():
            raise FileNotFoundError(
                f"YAML file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"YAML input is not a file: {path}"
            )

        if path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError(
                f"Input must be a YAML file: {path}"
            )

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        if not isinstance(data, dict):
            raise ValueError(
                f"YAML root must be a dictionary: {path}"
            )

        for element_key, element in data.items():
            if not isinstance(element, dict):
                raise ValueError(
                    f"{element_key} must be a dictionary."
                )

            name = element.get("name")
            requirements = element.get("requirements")

            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    f"{element_key} has an invalid KDE name."
                )

            if not isinstance(requirements, list):
                raise ValueError(
                    f"{element_key} requirements must be a list."
                )

            if not all(
                isinstance(requirement, str)
                for requirement in requirements
            ):
                raise ValueError(
                    f"{element_key} contains a non-string requirement."
                )

        loaded.append(data)

    return loaded[0], loaded[1]


def compare_kde_names(
    kde_data1: dict,
    kde_data2: dict,
    output_file: str | Path | None = None,
) -> str:
    """
    Compare KDE names between two Task 1 dictionaries.

    Returns differing names as TEXT, or the exact required
    no-differences message.
    """

    def normalize(name: str) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            " ",
            name.lower(),
        ).strip()

    names1 = {
        normalize(element["name"]): element["name"]
        for element in kde_data1.values()
    }

    names2 = {
        normalize(element["name"]): element["name"]
        for element in kde_data2.values()
    }

    different_keys = sorted(
        set(names1) ^ set(names2)
    )

    if not different_keys:
        result = NO_NAME_DIFFERENCES
    else:
        differences = []

        for key in different_keys:
            if key in names1:
                differences.append(names1[key])
            else:
                differences.append(names2[key])

        result = "\n".join(differences)

    if output_file is not None:
        output_path = Path(output_file)
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            result + "\n",
            encoding="utf-8",
        )

    return result


def compare_kde_requirements(
    kde_data1: dict,
    kde_data2: dict,
    output_file: str | Path | None = None,
) -> str:
    """
    Compare requirements associated with KDE names.

    Each difference is returned in the required:
        NAME,REQU
    TEXT format.
    """

    def normalize(name: str) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            " ",
            name.lower(),
        ).strip()

    def build_map(data: dict) -> dict:
        result = {}

        for element in data.values():
            name = element["name"]
            key = normalize(name)

            if key not in result:
                result[key] = {
                    "name": name,
                    "requirements": set(),
                }

            result[key]["requirements"].update(
                element["requirements"]
            )

        return result

    map1 = build_map(kde_data1)
    map2 = build_map(kde_data2)

    differences = []

    for key in sorted(set(map1) | set(map2)):
        requirements1 = (
            map1.get(
                key,
                {"requirements": set()},
            )["requirements"]
        )

        requirements2 = (
            map2.get(
                key,
                {"requirements": set()},
            )["requirements"]
        )

        different_requirements = sorted(
            requirements1 ^ requirements2
        )

        if not different_requirements:
            continue

        if key in map1:
            display_name = map1[key]["name"]
        else:
            display_name = map2[key]["name"]

        for requirement in different_requirements:
            differences.append(
                f"{display_name},{requirement}"
            )

    if differences:
        result = "\n".join(differences)
    else:
        result = NO_REQUIREMENT_DIFFERENCES

    if output_file is not None:
        output_path = Path(output_file)
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            result + "\n",
            encoding="utf-8",
        )

    return result
