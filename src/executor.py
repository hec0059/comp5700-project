"""Task 3: Map requirement changes to Hadolint and execute scans."""

from __future__ import annotations

from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import zipfile

import pandas as pd


NO_DIFFERENCES_FOUND = "NO DIFFERENCES FOUND"

TASK2_NO_DIFFERENCE_MESSAGES = {
    "NO DIFFERENCES IN REGARDS TO ELEMENT NAMES",
    "NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS",
    NO_DIFFERENCES_FOUND,
}

CSV_COLUMNS = [
    "FilePath",
    "DefaultSeverity",
    "RULEID",
    "COUNT",
]


# Hadolint DL rules documented for the installed 2.15.x rule set.
ALL_HADOLINT_RULES = {
    "DL1001",
    "DL3000",
    "DL3001",
    "DL3002",
    "DL3003",
    "DL3004",
    "DL3006",
    "DL3007",
    "DL3008",
    "DL3009",
    "DL3010",
    "DL3011",
    "DL3012",
    "DL3013",
    "DL3014",
    "DL3015",
    "DL3016",
    "DL3018",
    "DL3019",
    "DL3020",
    "DL3021",
    "DL3022",
    "DL3023",
    "DL3024",
    "DL3025",
    "DL3026",
    "DL3027",
    "DL3028",
    "DL3029",
    "DL3030",
    "DL3032",
    "DL3033",
    "DL3034",
    "DL3035",
    "DL3036",
    "DL3037",
    "DL3038",
    "DL3040",
    "DL3041",
    "DL3042",
    "DL3043",
    "DL3044",
    "DL3045",
    "DL3046",
    "DL3047",
    "DL3048",
    "DL3049",
    "DL3050",
    "DL3051",
    "DL3052",
    "DL3053",
    "DL3054",
    "DL3055",
    "DL3056",
    "DL3057",
    "DL3058",
    "DL3059",
    "DL3060",
    "DL3061",
    "DL4000",
    "DL4001",
    "DL4003",
    "DL4004",
    "DL4005",
    "DL4006",
}


# Manual/pattern-based mapping allowed by the project specification.
RULE_KEYWORDS = {
    "DL3000": (
        "absolute workdir",
    ),
    "DL3002": (
        "non-root",
        "non root",
        "root user",
        "run as root",
        "container user",
        "user for the container",
        "user privileges",
    ),
    "DL3003": (
        "workdir",
        "working directory",
    ),
    "DL3004": (
        "sudo",
        "privileged user",
    ),
    "DL3006": (
        "image tag",
        "tagged image",
        "base image version",
    ),
    "DL3007": (
        "latest image",
        "latest tag",
        "image version",
    ),
    "DL3008": (
        "apt-get",
        "apt package",
        "apt packages",
    ),
    "DL3009": (
        "apt lists",
        "apt-get lists",
    ),
    "DL3011": (
        "expose port",
        "exposed port",
        "port number",
    ),
    "DL3012": (
        "multiple healthcheck",
    ),
    "DL3013": (
        "pip package",
        "pip install",
    ),
    "DL3014": (
        "non-interactive apt",
        "apt -y",
    ),
    "DL3015": (
        "install recommends",
        "recommended packages",
    ),
    "DL3016": (
        "npm package",
        "npm install",
    ),
    "DL3018": (
        "apk package",
        "apk add",
    ),
    "DL3019": (
        "apk cache",
        "apk no-cache",
    ),
    "DL3020": (
        "copy instead of add",
        "add instruction",
        "copy instruction",
    ),
    "DL3021": (
        "copy arguments",
    ),
    "DL3022": (
        "copy --from",
        "multi-stage copy",
    ),
    "DL3024": (
        "from alias",
        "stage name",
    ),
    "DL3025": (
        "cmd",
        "entrypoint",
        "json notation",
    ),
    "DL3026": (
        "registry",
        "trusted registry",
        "image registry",
    ),
    "DL3027": (
        "apt command",
        "use apt",
    ),
    "DL3028": (
        "gem install",
        "gem package",
    ),
    "DL3029": (
        "--platform",
        "platform flag",
    ),
    "DL3030": (
        "yum install",
    ),
    "DL3032": (
        "yum clean",
    ),
    "DL3033": (
        "yum package",
        "yum version",
    ),
    "DL3034": (
        "zypper install",
    ),
    "DL3035": (
        "zypper dist-upgrade",
    ),
    "DL3036": (
        "zypper clean",
    ),
    "DL3037": (
        "zypper package",
        "zypper version",
    ),
    "DL3038": (
        "dnf install",
    ),
    "DL3040": (
        "dnf clean",
    ),
    "DL3041": (
        "dnf package",
        "dnf version",
    ),
    "DL3042": (
        "pip cache",
        "pip no-cache",
    ),
    "DL3045": (
        "relative copy destination",
    ),
    "DL3046": (
        "useradd",
        "user add",
    ),
    "DL3047": (
        "wget",
    ),
    "DL3048": (
        "label key",
    ),
    "DL3049": (
        "missing label",
    ),
    "DL3050": (
        "superfluous label",
    ),
    "DL3051": (
        "empty label",
    ),
    "DL3052": (
        "label url",
    ),
    "DL3053": (
        "label time",
        "label date",
    ),
    "DL3054": (
        "license label",
    ),
    "DL3055": (
        "git hash label",
    ),
    "DL3056": (
        "version label",
        "semantic version",
    ),
    "DL3057": (
        "healthcheck",
        "health check",
    ),
    "DL3058": (
        "email label",
    ),
    "DL3059": (
        "consecutive run",
        "multiple run instructions",
    ),
    "DL3060": (
        "yarn cache",
    ),
    "DL3061": (
        "instruction order",
    ),
    "DL4000": (
        "maintainer",
    ),
    "DL4001": (
        "wget and curl",
        "wget curl",
    ),
    "DL4003": (
        "multiple cmd",
    ),
    "DL4004": (
        "multiple entrypoint",
    ),
    "DL4005": (
        "shell instruction",
        "default shell",
    ),
    "DL4006": (
        "pipefail",
        "shell pipe",
    ),
}


def load_text_inputs(
    *text_files: str | Path,
) -> tuple[str, ...]:
    """
    Load and validate Task 2 TEXT files.

    The assignment inconsistently mentions both two and three
    Task 2 TEXT files, so this accepts two or more.
    """

    if len(text_files) < 2:
        raise ValueError(
            "At least two Task 2 TEXT files are required."
        )

    contents = []

    for value in text_files:
        path = Path(value)

        if not path.exists():
            raise FileNotFoundError(
                f"TEXT file does not exist: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"TEXT input is not a file: {path}"
            )

        if path.suffix.lower() != ".txt":
            raise ValueError(
                f"Input must be a .txt file: {path}"
            )

        text = path.read_text(
            encoding="utf-8",
        ).strip()

        if not text:
            raise ValueError(
                f"TEXT input is empty: {path}"
            )

        contents.append(text)

    return tuple(contents)


def map_differences_to_hadolint_rules(
    text_inputs: tuple[str, ...] | list[str],
    output_file: str | Path | None = None,
) -> str:
    """
    Map Task 2 differences to relevant Hadolint rules.

    Pattern matching is explicitly permitted by the project.
    If differences exist but no narrow mapping can be found,
    all Hadolint DL rules are returned conservatively.
    """

    if not isinstance(text_inputs, (tuple, list)):
        raise TypeError(
            "text_inputs must be a tuple or list of strings."
        )

    if len(text_inputs) < 2:
        raise ValueError(
            "At least two Task 2 outputs are required."
        )

    if not all(
        isinstance(text, str) and text.strip()
        for text in text_inputs
    ):
        raise ValueError(
            "Every Task 2 output must be a non-empty string."
        )

    meaningful_inputs = [
        text.strip()
        for text in text_inputs
        if text.strip() not in TASK2_NO_DIFFERENCE_MESSAGES
    ]

    if not meaningful_inputs:
        result = NO_DIFFERENCES_FOUND
    else:
        combined = "\n".join(
            meaningful_inputs
        ).lower()

        matched_rules = set()

        for rule_id, keywords in RULE_KEYWORDS.items():
            if any(
                keyword in combined
                for keyword in keywords
            ):
                matched_rules.add(rule_id)

        # A difference exists but the manual mapping cannot
        # associate it with a narrower Dockerfile rule.
        # Conservatively scan all Hadolint rules rather than
        # incorrectly treating the documents as unchanged.
        if not matched_rules:
            matched_rules = set(
                ALL_HADOLINT_RULES
            )

        result = "\n".join(
            sorted(matched_rules)
        )

    if output_file is not None:
        path = Path(output_file)
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            result + "\n",
            encoding="utf-8",
        )

    return result


def run_hadolint(
    dockerfiles_source: str | Path,
    rules_file: str | Path,
    hadolint_executable: str = "hadolint",
) -> pd.DataFrame:
    """
    Execute Hadolint on Dockerfiles from a ZIP file or directory.

    If rules_file contains NO DIFFERENCES FOUND, Hadolint runs
    normally with all available rules. Otherwise all documented
    DL rules except the selected rules are ignored and the final
    results are filtered to the selected rule IDs.
    """

    source = Path(dockerfiles_source)
    rule_path = Path(rules_file)

    if not source.exists():
        raise FileNotFoundError(
            f"Dockerfiles source does not exist: {source}"
        )

    if not rule_path.exists():
        raise FileNotFoundError(
            f"Rules file does not exist: {rule_path}"
        )

    executable = shutil.which(
        hadolint_executable
    )

    if executable is None:
        raise FileNotFoundError(
            f"Hadolint executable not found: "
            f"{hadolint_executable}"
        )

    rules_text = rule_path.read_text(
        encoding="utf-8",
    ).strip()

    if not rules_text:
        raise ValueError(
            "Hadolint rules file is empty."
        )

    run_all_rules = (
        rules_text == NO_DIFFERENCES_FOUND
    )

    selected_rules = set(
        re.findall(
            r"\b(?:DL|SC)\d{4}\b",
            rules_text,
            flags=re.IGNORECASE,
        )
    )

    selected_rules = {
        rule.upper()
        for rule in selected_rules
    }

    if not run_all_rules and not selected_rules:
        raise ValueError(
            "Rules file contains neither "
            "NO DIFFERENCES FOUND nor Hadolint rule IDs."
        )

    with tempfile.TemporaryDirectory(
        prefix="comp5700-hadolint-"
    ) as temp_directory:
        temp_path = Path(temp_directory)

        if source.is_file():
            if source.suffix.lower() != ".zip":
                raise ValueError(
                    "Dockerfiles source file must be a .zip archive."
                )

            extract_path = (
                temp_path / "dockerfiles"
            )
            extract_path.mkdir()

            with zipfile.ZipFile(
                source,
                "r",
            ) as archive:
                real_members = [
                    member
                    for member in archive.infolist()
                    if (
                        not member.is_dir()
                        and "dockerfile"
                        in Path(member.filename).name.lower()
                        and "__MACOSX"
                        not in Path(member.filename).parts
                        and not Path(member.filename).name.startswith("._")
                    )
                ]

                archive.extractall(
                    extract_path,
                    members=real_members,
                )

            scan_root = extract_path

        elif source.is_dir():
            scan_root = source

        else:
            raise ValueError(
                "Dockerfiles source must be a ZIP file "
                "or directory."
            )

        dockerfiles = sorted(
            path
            for path in scan_root.rglob("*")
            if (
                path.is_file()
                and "dockerfile" in path.name.lower()
                and "__MACOSX" not in path.parts
                and not path.name.startswith("._")
            )
        )

        if not dockerfiles:
            raise ValueError(
                "No Dockerfiles were found in the supplied source."
            )

        config_path = (
            temp_path / "hadolint.yaml"
        )

        config_path.write_text(
            "failure-threshold: ignore\n"
            "format: json\n",
            encoding="utf-8",
        )

        raw_rows = []
        batch_size = 250

        for batch_start in range(
            0,
            len(dockerfiles),
            batch_size,
        ):
            batch = dockerfiles[
                batch_start:
                batch_start + batch_size
            ]

            command = [
                executable,
                "--config",
                str(config_path),
                "--format",
                "json",
                "--no-fail",
            ]

            if not run_all_rules:
                ignored_rules = sorted(
                    ALL_HADOLINT_RULES
                    - selected_rules
                )

                for ignored_rule in ignored_rules:
                    command.extend(
                        [
                            "--ignore",
                            ignored_rule,
                        ]
                    )

            command.extend(
                str(dockerfile)
                for dockerfile in batch
            )

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

            if completed.returncode not in {
                0,
                1,
            }:
                raise RuntimeError(
                    "Hadolint failed for Dockerfile batch "
                    f"starting at index {batch_start}: "
                    f"{completed.stderr.strip()}"
                )

            stdout = completed.stdout.strip()

            if not stdout:
                continue

            try:
                decoder = json.JSONDecoder()
                findings = []
                position = 0

                while position < len(stdout):
                    while (
                        position < len(stdout)
                        and stdout[position].isspace()
                    ):
                        position += 1

                    if position >= len(stdout):
                        break

                    parsed, position = decoder.raw_decode(
                        stdout,
                        position,
                    )

                    if isinstance(parsed, list):
                        findings.extend(parsed)
                    elif isinstance(parsed, dict):
                        findings.append(parsed)

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    "Hadolint returned invalid JSON for "
                    f"Dockerfile batch starting at index "
                    f"{batch_start}."
                ) from exc

            for finding in findings:
                rule_id = str(
                    finding.get(
                        "code",
                        "",
                    )
                ).upper()

                if not rule_id:
                    continue

                if (
                    not run_all_rules
                    and rule_id
                    not in selected_rules
                ):
                    continue

                file_value = str(
                    finding.get(
                        "file",
                        "",
                    )
                )

                if file_value:
                    finding_path = Path(
                        file_value
                    )
                elif len(batch) == 1:
                    finding_path = batch[0]
                else:
                    continue

                try:
                    relative_path = (
                        finding_path.relative_to(
                            scan_root
                        )
                    )
                except ValueError:
                    relative_path = finding_path

                severity = str(
                    finding.get(
                        "level",
                        "",
                    )
                )

                raw_rows.append(
                    {
                        "FilePath": str(
                            relative_path
                        ),
                        "DefaultSeverity": severity,
                        "RULEID": rule_id,
                    }
                )

    if not raw_rows:
        return pd.DataFrame(
            columns=CSV_COLUMNS
        )

    dataframe = pd.DataFrame(
        raw_rows
    )

    dataframe = (
        dataframe
        .groupby(
            [
                "FilePath",
                "DefaultSeverity",
                "RULEID",
            ],
            as_index=False,
        )
        .size()
        .rename(
            columns={
                "size": "COUNT",
            }
        )
    )

    dataframe = dataframe[
        CSV_COLUMNS
    ].sort_values(
        by=[
            "FilePath",
            "RULEID",
            "DefaultSeverity",
        ],
        ignore_index=True,
    )

    return dataframe


def export_hadolint_csv(
    dataframe: pd.DataFrame,
    output_file: str | Path,
) -> Path:
    """
    Export Hadolint scan results to the required CSV format.
    """

    if not isinstance(
        dataframe,
        pd.DataFrame,
    ):
        raise TypeError(
            "dataframe must be a pandas DataFrame."
        )

    missing_columns = [
        column
        for column in CSV_COLUMNS
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "DataFrame is missing required columns: "
            + ", ".join(missing_columns)
        )

    path = Path(output_file)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    dataframe[
        CSV_COLUMNS
    ].to_csv(
        path,
        index=False,
    )

    return path
