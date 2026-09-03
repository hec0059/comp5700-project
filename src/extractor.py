from pathlib import Path
from typing import Tuple

from pypdf import PdfReader
from pypdf.errors import PdfReadError


def validate_pdf_inputs(
    document1: str | Path,
    document2: str | Path,
) -> Tuple[Path, Path]:
    """
    Validate two PDF documents supplied to the extractor.

    Validation checks:
    - each input exists;
    - each input is a file;
    - each input has a .pdf extension;
    - each input has a valid PDF file signature;
    - each input can be opened by pypdf;
    - each input contains at least one page.

    The same PDF may be supplied for both inputs because identical-document
    comparisons are valid project inputs.

    Returns:
        A tuple containing the two validated Path objects.

    Raises:
        TypeError: If an input is not a string or pathlib.Path.
        FileNotFoundError: If an input does not exist.
        ValueError: If an input is not a valid, readable PDF file.
    """

    validated_paths = []

    for document in (document1, document2):
        if not isinstance(document, (str, Path)):
            raise TypeError("Each document must be provided as a file path.")

        path = Path(document)

        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {path}")

        if not path.is_file():
            raise ValueError(f"Input path is not a file: {path}")

        if path.suffix.lower() != ".pdf":
            raise ValueError(f"Input file must be a PDF: {path}")

        try:
            with path.open("rb") as file:
                signature = file.read(5)

            if signature != b"%PDF-":
                raise ValueError(f"Input file does not have a valid PDF signature: {path}")

            reader = PdfReader(path)

            if len(reader.pages) == 0:
                raise ValueError(f"Input PDF contains no pages: {path}")

        except (PdfReadError, OSError) as exc:
            raise ValueError(f"Unable to read PDF file: {path}") from exc

        validated_paths.append(path)

    return validated_paths[0], validated_paths[1]


def build_zero_shot_prompt(document_text: str) -> str:
    """
    Construct a zero-shot prompt for mapping security requirements to KDEs.
    """

    if not isinstance(document_text, str):
        raise TypeError("document_text must be a string.")

    if not document_text.strip():
        raise ValueError("document_text must not be empty.")

    return f"""
You are analyzing CIS security requirements.

Each actual input line begins with a tag such as R001.

For EVERY actual R tag, identify the primary key data element (KDE).

A KDE is the short security-relevant subject, setting, file, service,
configuration item, resource, or control addressed by the requirement.

STRICT OUTPUT RULES:
- Output exactly one line for every supplied R tag.
- Preserve each R tag exactly.
- KDE names must be concise: preferably 2 to 6 words.
- Do not copy the complete requirement sentence as the KDE name.
- Do not begin KDE names with Ensure, Run, or Enable.
- Do not include Manual or Automated in KDE names.
- Do not invent or omit R tags.
- Output only YAML-compatible mapping lines.
- Do not include explanations or Markdown.

Required format:

R001: Short KDE Name
R002: Short KDE Name

ACTUAL SECURITY REQUIREMENTS:

{document_text}
""".strip()


def build_few_shot_prompt(document_text: str) -> str:
    """
    Construct a few-shot prompt for mapping security requirements to KDEs.
    """

    if not isinstance(document_text, str):
        raise TypeError("document_text must be a string.")

    if not document_text.strip():
        raise ValueError("document_text must not be empty.")

    return f"""
You are analyzing CIS security requirements.

Each actual input line begins with a tag such as R001.

For EVERY actual R tag, identify the primary key data element (KDE).

A KDE is the short security-relevant subject, setting, file, service,
configuration item, resource, or control addressed by the requirement.

EXAMPLE 1 - DEMONSTRATION ONLY:

EX001 | CIS-ID 1.1 | Require strong passwords.
EX002 | CIS-ID 1.2 | Passwords must contain at least 12 characters.

Correct demonstration output:

EX001: Passwords
EX002: Passwords

EXAMPLE 2 - SECOND DEMONSTRATION:

EX003 | CIS-ID 2.1 | Audit logs must be enabled.
EX004 | CIS-ID 2.2 | Audit logs must record failed login attempts.

Correct demonstration output:

EX003: Audit Logs
EX004: Audit Logs

The EX tags above are demonstrations only.
DO NOT output any EX tags for the actual task below.

STRICT OUTPUT RULES:
- Process only the actual R tags below.
- Output exactly one line for every supplied R tag.
- Preserve each R tag exactly.
- KDE names must be concise: preferably 2 to 6 words.
- Do not copy the complete requirement sentence as the KDE name.
- Do not begin KDE names with Ensure, Run, or Enable.
- Do not include Manual or Automated in KDE names.
- Do not invent or omit R tags.
- Output only YAML-compatible mapping lines.
- Do not include explanations or Markdown.

Required actual-output format:

R001: Short KDE Name
R002: Short KDE Name

ACTUAL SECURITY REQUIREMENTS:

{document_text}
""".strip()


def build_chain_of_thought_prompt(document_text: str) -> str:
    """
    Construct a chain-of-thought style prompt for mapping requirements to KDEs.
    """

    if not isinstance(document_text, str):
        raise TypeError("document_text must be a string.")

    if not document_text.strip():
        raise ValueError("document_text must not be empty.")

    return f"""
You are analyzing CIS security requirements.

Each actual input line begins with a tag such as R001.

For EVERY actual R tag, identify the primary key data element (KDE).

A KDE is the short security-relevant subject, setting, file, service,
configuration item, resource, or control addressed by the requirement.

Analyze the document systematically, one requirement at a time:
1. Identify statements that express security requirements.
2. Determine the primary security-relevant subject or configuration item.
3. Group requirements that refer to the same key data element conceptually.
4. Create a short and reusable KDE name.
5. Check that every supplied R tag has exactly one mapping.
6. Produce the final mapping.

Perform that reasoning internally. Do not include your intermediate reasoning in the response.

STRICT OUTPUT RULES:
- Output exactly one line for every supplied R tag.
- Preserve each R tag exactly.
- KDE names must be concise: preferably 2 to 6 words.
- Do not copy the complete requirement sentence as the KDE name.
- Do not begin KDE names with Ensure, Run, or Enable.
- Do not include Manual or Automated in KDE names.
- Do not invent or omit R tags.
- Output only YAML-compatible mapping lines.
- Do not include explanations or Markdown.

Required format:

R001: Short KDE Name
R002: Short KDE Name

ACTUAL SECURITY REQUIREMENTS:

{document_text}
""".strip()


def extract_kdes_with_gemma(
    document1: str | Path,
    document2: str | Path,
    output_dir: str | Path = "outputs/task1",
    model_id: str = "google/gemma-3-1b-it",
    max_chunk_chars: int = 14000,
    max_new_tokens: int = 1400,
    max_requirements_per_chunk: int = 30,
    generation_function=None,
):
    """
    Use Gemma-3-1B and all three prompting strategies to map CIS
    recommendations to key data elements and create nested KDE dictionaries.
    """

    import copy
    import logging
    import re

    import torch
    import yaml
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if max_chunk_chars <= 0:
        raise ValueError("max_chunk_chars must be greater than zero.")

    if max_new_tokens <= 0:
        raise ValueError("max_new_tokens must be greater than zero.")

    if max_requirements_per_chunk <= 0:
        raise ValueError(
            "max_requirements_per_chunk must be greater than zero."
        )

    pdf1, pdf2 = validate_pdf_inputs(document1, document2)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    logging.getLogger("pypdf").setLevel(logging.ERROR)

    prompt_builders = {
        "chain-of-thought": build_chain_of_thought_prompt,
        "few-shot": build_few_shot_prompt,
        "zero-shot": build_zero_shot_prompt,
    }

    def extract_pdf_text(pdf_path: Path) -> str:
        reader = PdfReader(pdf_path)
        pages = []

        for page in reader.pages:
            page_text = (page.extract_text() or "").strip()

            if page_text:
                pages.append(page_text)

        if not pages:
            raise ValueError(
                f"No extractable text found in PDF: {pdf_path}"
            )

        return "\n".join(pages)

    def extract_requirement_titles(text: str) -> list[str]:
        lines = [
            re.sub(r"\s+", " ", line).strip()
            for line in text.splitlines()
        ]

        requirements = []
        seen_ids = set()

        for index, line in enumerate(lines):
            heading_match = re.match(
                r"^(\d+(?:\.\d+)+)\s+(.+)$",
                line,
            )

            if not heading_match:
                continue

            requirement_id = heading_match.group(1)
            title_parts = [heading_match.group(2)]
            status = None

            for next_index in range(
                index,
                min(index + 4, len(lines)),
            ):
                if next_index == index:
                    candidate = title_parts[0]
                else:
                    continuation = lines[next_index]

                    if not continuation:
                        continue

                    if re.match(
                        r"^\d+(?:\.\d+)+\s+",
                        continuation,
                    ):
                        break

                    title_parts.append(continuation)
                    candidate = " ".join(title_parts)

                status_match = re.search(
                    r"\((Manual|Automated)\)\s*$",
                    candidate,
                    flags=re.IGNORECASE,
                )

                if status_match:
                    status = status_match.group(1).capitalize()
                    break

            if status is None:
                continue

            title = " ".join(title_parts)

            title = re.sub(
                r"\s*\((Manual|Automated)\)\s*$",
                "",
                title,
                flags=re.IGNORECASE,
            )

            title = re.sub(
                r"\.{2,}\s*\d+\s*$",
                "",
                title,
            )

            title = re.sub(r"\s+", " ", title).strip(" .")

            if not title or requirement_id in seen_ids:
                continue

            requirements.append(
                f"{requirement_id} {title} ({status})"
            )
            seen_ids.add(requirement_id)

        def numeric_key(requirement: str):
            requirement_id = requirement.split(" ", 1)[0]
            return tuple(
                int(part)
                for part in requirement_id.split(".")
            )

        requirements.sort(key=numeric_key)

        return requirements

    def make_requirement_entries(
        requirements: list[str],
    ) -> dict[str, str]:
        entries = {}

        for requirement in requirements:
            requirement_id, rest = requirement.split(" ", 1)
            entries[requirement_id] = (
                f"{requirement_id} {rest}"
            )

        return entries

    def split_requirements(
        requirements: list[str],
    ) -> list[list[str]]:
        chunks = []
        current = []
        current_length = 0

        for requirement in requirements:
            line = f"REQUIREMENT: {requirement}"
            line_length = len(line) + 1

            reached_count_limit = (
                len(current)
                >= max_requirements_per_chunk
            )

            reached_character_limit = (
                current
                and current_length + line_length
                > max_chunk_chars
            )

            if current and (
                reached_count_limit
                or reached_character_limit
            ):
                chunks.append(current)
                current = []
                current_length = 0

            current.append(requirement)
            current_length += line_length

        if current:
            chunks.append(current)

        return chunks


    def parse_mapping(
        raw_output: str,
        allowed_tags: set[str],
    ) -> dict[str, str]:
        mappings = {}

        cleaned = raw_output.strip()
        cleaned = cleaned.replace("```yaml", "")
        cleaned = cleaned.replace("```yml", "")
        cleaned = cleaned.replace("```", "")

        for line in cleaned.splitlines():
            line = line.strip().lstrip("-* ").strip()

            match = re.match(
                r"""^["']?(R\d{3,4})["']?
                    \s*(?::|\||->|=)\s*
                    ["']?(.+?)["']?\s*$""",
                line,
                flags=re.VERBOSE | re.IGNORECASE,
            )

            if not match:
                continue

            tag = match.group(1).upper().strip()
            kde_name = match.group(2).strip()

            kde_name = re.sub(
                r"\s+",
                " ",
                kde_name,
            ).strip(" ,.;:'\"")

            if tag not in allowed_tags:
                continue

            if not kde_name:
                continue

            if kde_name.lower().startswith("requirement"):
                continue

            if "treat each line" in kde_name.lower():
                continue

            mappings[tag] = kde_name

        return mappings

    def normalize_kde(name: str) -> str:
        return re.sub(
            r"[^a-z0-9]+",
            " ",
            name.lower(),
        ).strip()

    tokenizer = None
    model = None
    device = None

    if generation_function is None:
        print(f"Loading required model: {model_id}")

        tokenizer = AutoTokenizer.from_pretrained(model_id)

        device = torch.device(
            "mps"
            if torch.backends.mps.is_available()
            else "cpu"
        )

        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            dtype=(
                torch.float16
                if device.type == "mps"
                else torch.float32
            ),
        ).to(device)

        model.eval()

        def generation_function(prompt: str) -> str:
            messages = [
                {
                    "role": "user",
                    "content": prompt,
                }
            ]

            model_inputs = tokenizer.apply_chat_template(
                messages,
                add_generation_prompt=True,
                tokenize=True,
                return_dict=True,
                return_tensors="pt",
            ).to(device)

            with torch.no_grad():
                generated = model.generate(
                    **model_inputs,
                    max_new_tokens=max_new_tokens,
                    do_sample=False,
                )

            new_tokens = generated[
                0,
                model_inputs["input_ids"].shape[-1]:,
            ]

            return tokenizer.decode(
                new_tokens,
                skip_special_tokens=True,
            ).strip()

    results = {}
    llm_records = []
    processed_documents = {}

    input_paths = (pdf1, pdf2)
    duplicate_stems = pdf1.stem == pdf2.stem

    for input_number, pdf_path in enumerate(
        input_paths,
        start=1,
    ):
        cache_key = str(pdf_path.resolve())

        if cache_key in processed_documents:
            print(
                f"\nReusing previously generated KDEs for "
                f"{pdf_path.name}..."
            )

            merged_kdes = copy.deepcopy(
                processed_documents[cache_key]
            )

        else:
            print(f"\nReading {pdf_path.name}...")

            document_text = extract_pdf_text(pdf_path)
            requirements = extract_requirement_titles(
                document_text
            )

            if not requirements:
                raise ValueError(
                    f"No numbered CIS recommendation titles "
                    f"were found in {pdf_path.name}."
                )

            requirement_entries = make_requirement_entries(
                requirements
            )

            requirement_id_to_tag = {
                requirement_id: f"R{index:03d}"
                for index, requirement_id in enumerate(
                    requirement_entries,
                    start=1,
                )
            }

            tag_to_requirement_id = {
                tag: requirement_id
                for requirement_id, tag
                in requirement_id_to_tag.items()
            }

            chunks = split_requirements(requirements)

            print(
                f"{pdf_path.name}: "
                f"{len(requirements)} authoritative "
                f"recommendation titles"
            )

            print(
                f"{pdf_path.name}: {len(chunks)} chunks"
            )

            mappings_by_prompt = {
                prompt_type: {}
                for prompt_type in prompt_builders
            }

            for prompt_type, prompt_builder in (
                prompt_builders.items()
            ):
                print(f"Running {prompt_type} prompting...")

                for chunk_number, chunk in enumerate(
                    chunks,
                    start=1,
                ):
                    print(
                        f"  {pdf_path.name} | "
                        f"{prompt_type} | "
                        f"chunk {chunk_number}/{len(chunks)}"
                    )

                    chunk_lines = []

                    for requirement in chunk:
                        requirement_id, rest = (
                            requirement.split(" ", 1)
                        )

                        tag = requirement_id_to_tag[
                            requirement_id
                        ]

                        chunk_lines.append(
                            f"{tag} | CIS-ID "
                            f"{requirement_id} | {rest}"
                        )

                    chunk_text = "\n".join(chunk_lines)

                    prompt = prompt_builder(chunk_text)
                    raw_output = generation_function(prompt)

                    llm_records.append(
                        {
                            "llm_name": model_id,
                            "document": pdf_path.name,
                            "prompt_type": prompt_type,
                            "prompt_used": prompt,
                            "llm_output": raw_output,
                            "chunk_number": chunk_number,
                        }
                    )

                    allowed_tags = {
                        requirement_id_to_tag[
                            requirement.split(" ", 1)[0]
                        ]
                        for requirement in chunk
                    }

                    parsed_tags = parse_mapping(
                        raw_output,
                        allowed_tags,
                    )

                    parsed_requirements = {
                        tag_to_requirement_id[tag]: kde_name
                        for tag, kde_name
                        in parsed_tags.items()
                    }

                    mappings_by_prompt[
                        prompt_type
                    ].update(parsed_requirements)

            selected_mappings = {}

            priority = [
                "chain-of-thought",
                "few-shot",
                "zero-shot",
            ]

            for requirement_id in requirement_entries:
                candidates = []

                for prompt_type in priority:
                    kde_name = mappings_by_prompt[
                        prompt_type
                    ].get(requirement_id)

                    if kde_name:
                        candidates.append(
                            (prompt_type, kde_name)
                        )

                if not candidates:
                    continue

                normalized_counts = {}

                for _, kde_name in candidates:
                    normalized = normalize_kde(kde_name)
                    normalized_counts[normalized] = (
                        normalized_counts.get(
                            normalized,
                            0,
                        )
                        + 1
                    )

                majority = max(
                    normalized_counts,
                    key=normalized_counts.get,
                )

                if normalized_counts[majority] >= 2:
                    chosen = next(
                        kde_name
                        for _, kde_name in candidates
                        if normalize_kde(kde_name)
                        == majority
                    )
                else:
                    chosen = candidates[0][1]

                selected_mappings[
                    requirement_id
                ] = chosen

            missing_ids = [
                requirement_id
                for requirement_id in requirement_entries
                if requirement_id not in selected_mappings
            ]

            if missing_ids:
                print(
                    f"{pdf_path.name}: "
                    f"{len(missing_ids)} requirements missing; "
                    f"retrying only missing requirements..."
                )

            retry_rounds = (
                (15, 1),
                (5, 2),
            )

            for retry_batch_size, retry_round in retry_rounds:
                if not missing_ids:
                    break

                retry_batches = [
                    missing_ids[index:index + retry_batch_size]
                    for index in range(
                        0,
                        len(missing_ids),
                        retry_batch_size,
                    )
                ]

                for retry_number, retry_ids in enumerate(
                    retry_batches,
                    start=1,
                ):
                    print(
                        f"  {pdf_path.name} | "
                        f"zero-shot retry {retry_round} | "
                        f"batch {retry_number}/"
                        f"{len(retry_batches)}"
                    )

                    retry_lines = []

                    for requirement_id in retry_ids:
                        full_requirement = requirement_entries[
                            requirement_id
                        ]

                        _, requirement_text = (
                            full_requirement.split(" ", 1)
                        )

                        tag = requirement_id_to_tag[
                            requirement_id
                        ]

                        retry_lines.append(
                            f"{tag} | CIS-ID "
                            f"{requirement_id} | "
                            f"{requirement_text}"
                        )

                    retry_text = "\n".join(retry_lines)
                    retry_prompt = build_zero_shot_prompt(
                        retry_text
                    )

                    retry_output = generation_function(
                        retry_prompt
                    )

                    llm_records.append(
                        {
                            "llm_name": model_id,
                            "document": pdf_path.name,
                            "prompt_type": "zero-shot",
                            "prompt_used": retry_prompt,
                            "llm_output": retry_output,
                            "chunk_number": (
                                f"retry-{retry_round}-"
                                f"{retry_number}"
                            ),
                        }
                    )

                    allowed_retry_tags = {
                        requirement_id_to_tag[
                            requirement_id
                        ]
                        for requirement_id in retry_ids
                    }

                    parsed_retry_tags = parse_mapping(
                        retry_output,
                        allowed_retry_tags,
                    )

                    for tag, kde_name in (
                        parsed_retry_tags.items()
                    ):
                        requirement_id = (
                            tag_to_requirement_id[tag]
                        )

                        selected_mappings[
                            requirement_id
                        ] = kde_name

                missing_ids = [
                    requirement_id
                    for requirement_id in requirement_entries
                    if requirement_id
                    not in selected_mappings
                ]

            if missing_ids:
                raise ValueError(
                    f"Gemma failed to map "
                    f"{len(missing_ids)} requirements "
                    f"for {pdf_path.name}: "
                    + ", ".join(missing_ids)
                )

            if not selected_mappings:
                raise ValueError(
                    f"Gemma returned no usable KDE mappings "
                    f"for {pdf_path.name}."
                )

            print(
                f"{pdf_path.name}: "
                f"{len(selected_mappings)}/"
                f"{len(requirement_entries)} requirements mapped"
            )

            grouped = {}
            display_names = {}

            for requirement_id, kde_name in (
                selected_mappings.items()
            ):
                normalized = normalize_kde(kde_name)

                if normalized not in grouped:
                    grouped[normalized] = []
                    display_names[normalized] = kde_name

                grouped[normalized].append(
                    requirement_entries[requirement_id]
                )

            merged_kdes = {}

            for index, normalized in enumerate(
                grouped,
                start=1,
            ):
                merged_kdes[f"element{index}"] = {
                    "name": display_names[normalized],
                    "requirements": grouped[normalized],
                }

            processed_documents[cache_key] = (
                copy.deepcopy(merged_kdes)
            )

        if duplicate_stems:
            result_key = (
                f"input{input_number}:{pdf_path.name}"
            )

            yaml_filename = (
                output_path
                / (
                    f"{pdf_path.stem}-"
                    f"input{input_number}-kdes.yaml"
                )
            )
        else:
            result_key = pdf_path.name

            yaml_filename = (
                output_path
                / f"{pdf_path.stem}-kdes.yaml"
            )

        results[result_key] = merged_kdes

        with yaml_filename.open(
            "w",
            encoding="utf-8",
        ) as yaml_file:
            yaml.safe_dump(
                merged_kdes,
                yaml_file,
                sort_keys=False,
                allow_unicode=True,
            )

        print(f"Saved KDE YAML: {yaml_filename}")

    # Reconcile KDE names for requirements that are textually identical
    # in both input documents. This prevents unchanged requirements from
    # appearing changed merely because the LLM chose different KDE wording.
    if len(results) == 2:
        result_keys = list(results.keys())

        def requirement_name_map(kdes):
            mapping = {}

            for element in kdes.values():
                for requirement in element["requirements"]:
                    mapping[requirement] = element["name"]

            return mapping

        def normalize_name(name):
            return re.sub(
                r"[^a-z0-9]+",
                " ",
                name.lower(),
            ).strip()

        def meaningful_tokens(value):
            stop_words = {
                "a", "an", "and", "are", "as", "at", "be", "been",
                "by", "for", "from", "has", "have", "if", "in", "is",
                "it", "of", "on", "only", "or", "set", "that", "the",
                "this", "to", "with", "ensure", "run", "enable",
                "manual", "automated",
            }

            return [
                token
                for token in re.findall(
                    r"[a-z0-9]+",
                    value.lower(),
                )
                if token not in stop_words
            ]

        def kde_quality(name, requirement):
            name_tokens = meaningful_tokens(name)
            requirement_tokens = set(
                meaningful_tokens(requirement)
            )

            overlap = sum(
                token in requirement_tokens
                for token in name_tokens
            )

            unrelated = sum(
                token not in requirement_tokens
                for token in name_tokens
            )

            return (
                overlap * 10
                - unrelated
                - len(name_tokens) * 0.01
            )

        maps = [
            requirement_name_map(results[key])
            for key in result_keys
        ]

        shared_requirements = (
            set(maps[0]) & set(maps[1])
        )

        canonical_names = {}

        for requirement in shared_requirements:
            first_name = maps[0][requirement]
            second_name = maps[1][requirement]

            if (
                normalize_name(first_name)
                == normalize_name(second_name)
            ):
                canonical_names[requirement] = first_name
                continue

            first_score = kde_quality(
                first_name,
                requirement,
            )

            second_score = kde_quality(
                second_name,
                requirement,
            )

            if second_score > first_score:
                chosen = second_name
            elif first_score > second_score:
                chosen = first_name
            else:
                chosen = min(
                    (first_name, second_name),
                    key=lambda value: (
                        len(meaningful_tokens(value)),
                        len(value),
                        value.lower(),
                    ),
                )

            canonical_names[requirement] = chosen

        def rebuild_kdes(kdes):
            rebuilt_groups = {}
            display_names = {}

            for element in kdes.values():
                original_name = element["name"]

                for requirement in element["requirements"]:
                    chosen_name = canonical_names.get(
                        requirement,
                        original_name,
                    )

                    normalized = normalize_name(
                        chosen_name
                    )

                    if normalized not in rebuilt_groups:
                        rebuilt_groups[normalized] = []
                        display_names[normalized] = (
                            chosen_name
                        )

                    rebuilt_groups[
                        normalized
                    ].append(requirement)

            return {
                f"element{index}": {
                    "name": display_names[normalized],
                    "requirements": requirements,
                }
                for index, (
                    normalized,
                    requirements,
                ) in enumerate(
                    rebuilt_groups.items(),
                    start=1,
                )
            }

        for key in result_keys:
            results[key] = rebuild_kdes(
                results[key]
            )

        # Rewrite the already-created YAML files with the reconciled data.
        for input_number, pdf_path in enumerate(
            input_paths,
            start=1,
        ):
            if duplicate_stems:
                result_key = (
                    f"input{input_number}:"
                    f"{pdf_path.name}"
                )

                yaml_filename = (
                    output_path
                    / (
                        f"{pdf_path.stem}-"
                        f"input{input_number}-kdes.yaml"
                    )
                )
            else:
                result_key = pdf_path.name

                yaml_filename = (
                    output_path
                    / f"{pdf_path.stem}-kdes.yaml"
                )

            with yaml_filename.open(
                "w",
                encoding="utf-8",
            ) as yaml_file:
                yaml.safe_dump(
                    results[result_key],
                    yaml_file,
                    sort_keys=False,
                    allow_unicode=True,
                )

        print(
            f"Cross-document reconciliation checked "
            f"{len(shared_requirements)} identical requirements."
        )

    return results, llm_records


def save_llm_outputs(
    llm_records: list[dict],
    output_file: str | Path = "outputs/task1/llm_outputs.txt",
) -> Path:
    """
    Save collected LLM execution records to a formatted text file.

    Each record must contain:
    - llm_name
    - prompt_used
    - prompt_type
    - llm_output

    Args:
        llm_records: List of dictionaries containing LLM execution data.
        output_file: Destination text file.

    Returns:
        Path to the created text file.

    Raises:
        TypeError: If llm_records is not a list.
        ValueError: If records are missing required fields.
    """

    if not isinstance(llm_records, list):
        raise TypeError("llm_records must be a list.")

    required_fields = {
        "llm_name",
        "prompt_used",
        "prompt_type",
        "llm_output",
    }

    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    formatted_records = []

    for record in llm_records:
        if not isinstance(record, dict):
            raise ValueError("Each LLM record must be a dictionary.")

        missing_fields = required_fields - record.keys()

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            raise ValueError(
                f"LLM record is missing required fields: {missing}"
            )

        formatted_record = (
            "*LLM Name*\n"
            f"{record['llm_name']}\n\n"
            "*Prompt Used*\n"
            f"{record['prompt_used']}\n\n"
            "*Prompt Type*\n"
            f"{record['prompt_type']}\n\n"
            "*LLM Output*\n"
            f"{record['llm_output']}\n"
        )

        formatted_records.append(formatted_record)

    output_path.write_text(
        "\n----------------------------------------\n\n".join(
            formatted_records
        ),
        encoding="utf-8",
    )

    return output_path
