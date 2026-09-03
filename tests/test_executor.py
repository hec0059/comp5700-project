"""Tests for Task 3 executor functions."""

from pathlib import Path
import json
import subprocess
import zipfile

import pandas as pd
import pytest

import src.executor as executor
from src.executor import (
    NO_DIFFERENCES_FOUND,
    export_hadolint_csv,
    load_text_inputs,
    map_differences_to_hadolint_rules,
    run_hadolint,
)


def test_load_text_inputs(tmp_path):
    """Test loading Task 2 TEXT files."""

    first = tmp_path / "names.txt"
    second = tmp_path / "requirements.txt"

    first.write_text(
        "Docker User",
        encoding="utf-8",
    )

    second.write_text(
        "Docker User,Run container as non-root",
        encoding="utf-8",
    )

    loaded = load_text_inputs(
        first,
        second,
    )

    assert len(loaded) == 2
    assert loaded[0] == "Docker User"

    with pytest.raises(
        FileNotFoundError
    ):
        load_text_inputs(
            first,
            tmp_path / "missing.txt",
        )


def test_map_differences_to_hadolint_rules(
    tmp_path,
):
    """Test difference-to-Hadolint-rule mapping."""

    output = tmp_path / "rules.txt"

    result = map_differences_to_hadolint_rules(
        (
            "Container User",
            "Container User,"
            "Ensure that a user for the container "
            "has been created",
        ),
        output,
    )

    assert "DL3002" in result
    assert output.exists()

    no_difference = (
        map_differences_to_hadolint_rules(
            (
                "NO DIFFERENCES IN REGARDS "
                "TO ELEMENT NAMES",
                "NO DIFFERENCES IN REGARDS "
                "TO ELEMENT REQUIREMENTS",
            )
        )
    )

    assert (
        no_difference
        == NO_DIFFERENCES_FOUND
    )


def test_run_hadolint(
    tmp_path,
    monkeypatch,
):
    """
    Test batched Hadolint execution and ZIP metadata filtering.
    """
    source_directory = (
        tmp_path / "source"
    )
    source_directory.mkdir()

    first = (
        source_directory / "First.Dockerfile"
    )
    first.write_text(
        "FROM ubuntu:latest\nUSER root\n",
        encoding="utf-8",
    )

    second = (
        source_directory / "Second.Dockerfile"
    )
    second.write_text(
        "FROM alpine:latest\n",
        encoding="utf-8",
    )

    metadata = (
        source_directory / "._First.Dockerfile"
    )
    metadata.write_text(
        "metadata",
        encoding="utf-8",
    )

    archive_path = (
        tmp_path / "dockerfiles.zip"
    )

    with zipfile.ZipFile(
        archive_path,
        "w",
    ) as archive:
        archive.write(
            first,
            arcname="sample/First.Dockerfile",
        )
        archive.write(
            second,
            arcname="sample/Second.Dockerfile",
        )
        archive.write(
            metadata,
            arcname=(
                "__MACOSX/sample/"
                "._First.Dockerfile"
            ),
        )

    rules_file = (
        tmp_path / "rules.txt"
    )
    rules_file.write_text(
        "NO DIFFERENCES FOUND\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        executor.shutil,
        "which",
        lambda value: "/usr/bin/hadolint",
    )

    commands = []

    def fake_run(
        command,
        capture_output,
        text,
        check,
    ):
        commands.append(command)

        dockerfiles = [
            value
            for value in command
            if value.endswith(".Dockerfile")
        ]

        assert len(dockerfiles) == 2
        assert not any(
            "._First.Dockerfile" in value
            for value in dockerfiles
        )

        first_json = json.dumps(
            [
                {
                    "code": "DL3002",
                    "file": dockerfiles[0],
                    "level": "warning",
                }
            ]
        )

        second_json = json.dumps(
            [
                {
                    "code": "DL3006",
                    "file": dockerfiles[1],
                    "level": "warning",
                }
            ]
        )

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=first_json + "\n" + second_json,
            stderr="",
        )

    monkeypatch.setattr(
        executor.subprocess,
        "run",
        fake_run,
    )

    dataframe = run_hadolint(
        archive_path,
        rules_file,
    )

    assert len(commands) == 1

    assert list(
        dataframe.columns
    ) == [
        "FilePath",
        "DefaultSeverity",
        "RULEID",
        "COUNT",
    ]

    assert len(dataframe) == 2

    assert set(
        dataframe["RULEID"]
    ) == {
        "DL3002",
        "DL3006",
    }

    assert all(
        "__MACOSX" not in value
        for value in dataframe["FilePath"]
    )


def test_export_hadolint_csv(
    tmp_path,
):
    """Test required Task 3 CSV export."""

    dataframe = pd.DataFrame(
        [
            {
                "FilePath": "sample/Dockerfile",
                "DefaultSeverity": "warning",
                "RULEID": "DL3002",
                "COUNT": 1,
            }
        ]
    )

    output = (
        tmp_path / "results.csv"
    )

    result = export_hadolint_csv(
        dataframe,
        output,
    )

    assert result == output
    assert output.exists()

    exported = pd.read_csv(
        output
    )

    assert list(
        exported.columns
    ) == [
        "FilePath",
        "DefaultSeverity",
        "RULEID",
        "COUNT",
    ]
