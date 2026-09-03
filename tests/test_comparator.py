"""Tests for Task 2 comparator functions."""

from pathlib import Path

import pytest
import yaml

from src.comparator import (
    NO_NAME_DIFFERENCES,
    NO_REQUIREMENT_DIFFERENCES,
    compare_kde_names,
    compare_kde_requirements,
    load_yaml_inputs,
)


def test_load_yaml_inputs(tmp_path):
    """Test loading and validation of two KDE YAML files."""

    data = {
        "element1": {
            "name": "Docker Daemon",
            "requirements": [
                "1.1 Ensure Docker daemon auditing is enabled"
            ],
        }
    }

    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"

    for path in (first, second):
        path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
            ),
            encoding="utf-8",
        )

    loaded1, loaded2 = load_yaml_inputs(
        first,
        second,
    )

    assert loaded1 == data
    assert loaded2 == data

    with pytest.raises(FileNotFoundError):
        load_yaml_inputs(
            tmp_path / "missing.yaml",
            second,
        )


def test_compare_kde_names(tmp_path):
    """Test KDE name comparison and TEXT output."""

    first = {
        "element1": {
            "name": "Docker Daemon",
            "requirements": ["Requirement A"],
        },
        "element2": {
            "name": "Audit Logs",
            "requirements": ["Requirement B"],
        },
    }

    second = {
        "element1": {
            "name": "Docker Daemon",
            "requirements": ["Requirement A"],
        },
        "element2": {
            "name": "Container Images",
            "requirements": ["Requirement C"],
        },
    }

    output = tmp_path / "names.txt"

    result = compare_kde_names(
        first,
        second,
        output,
    )

    assert "Audit Logs" in result
    assert "Container Images" in result
    assert output.exists()

    assert (
        compare_kde_names(first, first)
        == NO_NAME_DIFFERENCES
    )


def test_compare_kde_requirements(tmp_path):
    """Test KDE requirement comparison and TEXT output."""

    first = {
        "element1": {
            "name": "Docker Daemon",
            "requirements": [
                "Requirement A",
                "Requirement B",
            ],
        }
    }

    second = {
        "element1": {
            "name": "Docker Daemon",
            "requirements": [
                "Requirement A",
                "Requirement C",
            ],
        }
    }

    output = tmp_path / "requirements.txt"

    result = compare_kde_requirements(
        first,
        second,
        output,
    )

    assert "Docker Daemon,Requirement B" in result
    assert "Docker Daemon,Requirement C" in result
    assert output.exists()

    assert (
        compare_kde_requirements(first, first)
        == NO_REQUIREMENT_DIFFERENCES
    )
