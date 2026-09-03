"""Command-line entry point for the COMP 5700 project."""

from argparse import ArgumentParser
from pathlib import Path

from src.extractor import (
    extract_kdes_with_gemma,
    save_llm_outputs,
)
from src.comparator import (
    compare_kde_names,
    compare_kde_requirements,
)
from src.executor import (
    export_hadolint_csv,
    map_differences_to_hadolint_rules,
    run_hadolint,
)


def main():
    parser = ArgumentParser(
        description=(
            "Compare two CIS Docker Benchmark PDFs and "
            "determine relevant Hadolint rules."
        )
    )

    parser.add_argument(
        "document1",
        help="Path to the first CIS Docker Benchmark PDF.",
    )

    parser.add_argument(
        "document2",
        help="Path to the second CIS Docker Benchmark PDF.",
    )

    parser.add_argument(
        "--output-dir",
        default="outputs/run",
        help="Directory for generated project outputs.",
    )

    parser.add_argument(
        "--dockerfiles",
        default="dockerfiles.zip",
        help=(
            "Path to the Dockerfiles ZIP archive or directory. "
            "Defaults to dockerfiles.zip."
        ),
    )

    args = parser.parse_args()

    output_root = Path(args.output_dir)
    task1_dir = output_root / "task1"
    task2_dir = output_root / "task2"
    task3_dir = output_root / "task3"

    task1_dir.mkdir(parents=True, exist_ok=True)
    task2_dir.mkdir(parents=True, exist_ok=True)
    task3_dir.mkdir(parents=True, exist_ok=True)

    print("\n========================================")
    print("COMP 5700 PROJECT")
    print("========================================")
    print(f"Document 1: {args.document1}")
    print(f"Document 2: {args.document2}")
    print()

    results, records = extract_kdes_with_gemma(
        args.document1,
        args.document2,
        output_dir=task1_dir,
        max_chunk_chars=50000,
        max_requirements_per_chunk=30,
        max_new_tokens=700,
    )

    save_llm_outputs(
        records,
        output_file=task1_dir / "llm_outputs.txt",
    )

    result_keys = list(results)

    if len(result_keys) != 2:
        raise RuntimeError(
            "Expected exactly two KDE result dictionaries."
        )

    first = results[result_keys[0]]
    second = results[result_keys[1]]

    names_file = (
        task2_dir / "kde_name_differences.txt"
    )

    requirements_file = (
        task2_dir / "kde_requirement_differences.txt"
    )

    names_text = compare_kde_names(
        first,
        second,
        names_file,
    )

    requirements_text = compare_kde_requirements(
        first,
        second,
        requirements_file,
    )

    rules_file = task3_dir / "hadolint_rules.txt"

    rules_text = map_differences_to_hadolint_rules(
        (
            names_text,
            requirements_text,
        ),
        rules_file,
    )

    dockerfiles_path = Path(args.dockerfiles)

    if not dockerfiles_path.exists():
        raise FileNotFoundError(
            f"Dockerfiles input not found: {dockerfiles_path}. "
            "Provide the course Dockerfiles archive with "
            "--dockerfiles PATH."
        )

    print("\nRunning Hadolint...")

    dataframe = run_hadolint(
        dockerfiles_path,
        rules_file,
    )

    csv_file = export_hadolint_csv(
        dataframe,
        task3_dir / "hadolint_results.csv",
    )

    print("\n========================================")
    print("PROCESSING COMPLETE")
    print("========================================")
    print(f"Task 1 outputs: {task1_dir}")
    print(f"Task 2 outputs: {task2_dir}")
    print(f"Hadolint rules: {rules_file}")
    print(f"Hadolint CSV: {csv_file}")
    print()
    print("Selected Hadolint rules:")
    print(rules_text)


if __name__ == "__main__":
    main()
