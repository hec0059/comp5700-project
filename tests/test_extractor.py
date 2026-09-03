import re
from pathlib import Path

from pypdf import PdfWriter

from src.extractor import (
    validate_pdf_inputs,
    build_zero_shot_prompt,
    build_few_shot_prompt,
    build_chain_of_thought_prompt,
    save_llm_outputs,
)


def test_validate_pdf_inputs(tmp_path: Path):
    """Test that two valid PDF files are accepted."""

    pdf1 = tmp_path / "document1.pdf"
    pdf2 = tmp_path / "document2.pdf"

    for pdf_path in (pdf1, pdf2):
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)

        with pdf_path.open("wb") as file:
            writer.write(file)

    result1, result2 = validate_pdf_inputs(pdf1, pdf2)

    assert result1 == pdf1
    assert result2 == pdf2


def test_build_zero_shot_prompt():
    """Test that the zero-shot prompt is constructed correctly."""

    sample_text = (
        "Ensure that a user for the container has been created. "
        "Containers should not run as root."
    )

    prompt = build_zero_shot_prompt(sample_text)

    assert isinstance(prompt, str)
    assert sample_text in prompt
    assert "key data element" in prompt.lower()
    assert "requirements" in prompt.lower()
    assert "yaml-compatible" in prompt.lower()


def test_build_few_shot_prompt():
    """Test that the few-shot prompt is constructed correctly."""

    sample_text = (
        "The Docker daemon must be securely configured. "
        "Only trusted users should be allowed access."
    )

    prompt = build_few_shot_prompt(sample_text)

    assert isinstance(prompt, str)
    assert sample_text in prompt
    assert "EXAMPLE 1" in prompt
    assert "EXAMPLE 2" in prompt
    assert "Passwords" in prompt
    assert "Audit logs" in prompt
    assert "yaml-compatible" in prompt.lower()


def test_build_chain_of_thought_prompt():
    """Test that the chain-of-thought prompt is constructed correctly."""

    sample_text = (
        "Container images should be scanned for vulnerabilities. "
        "Images should be rebuilt after security patches are released."
    )

    prompt = build_chain_of_thought_prompt(sample_text)

    assert isinstance(prompt, str)
    assert sample_text in prompt
    assert "Analyze the document systematically" in prompt
    assert "Identify statements that express security requirements" in prompt
    assert "Group requirements that refer to the same key data element" in prompt
    assert "Do not include your intermediate reasoning" in prompt
    assert "yaml-compatible" in prompt.lower()


def test_extract_kdes_with_gemma(tmp_path, monkeypatch):
    """Test KDE extraction without loading the real Gemma model."""

    from pypdf import PdfWriter
    import src.extractor as extractor

    pdf1 = tmp_path / "first.pdf"
    pdf2 = tmp_path / "second.pdf"

    for pdf_path in (pdf1, pdf2):
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)

        with pdf_path.open("wb") as file:
            writer.write(file)

    real_pdf_reader = extractor.PdfReader

    class FakePage:
        def extract_text(self):
            return (
                "1.1.1 Ensure audit logs are enabled (Automated)\n"
                "1.1.2 Ensure audit logs record security events (Automated)"
            )

    class FakeReader:
        def __init__(self, path):
            self.pages = [FakePage()]

    validation_calls = {"count": 0}

    def reader_for_test(path):
        if validation_calls["count"] < 2:
            validation_calls["count"] += 1
            return real_pdf_reader(path)

        return FakeReader(path)

    monkeypatch.setattr(
        extractor,
        "PdfReader",
        reader_for_test,
    )

    def fake_generation(prompt):
        tags = re.findall(
            r"^(R\d{3,4}) \| CIS-ID",
            prompt,
            flags=re.MULTILINE,
        )

        return "\n".join(
            f"{tag}: Audit logs"
            for tag in tags
        )

    output_dir = tmp_path / "outputs"

    results, records = extractor.extract_kdes_with_gemma(
        pdf1,
        pdf2,
        output_dir=output_dir,
        max_chunk_chars=5000,
        generation_function=fake_generation,
    )

    assert "first.pdf" in results
    assert "second.pdf" in results

    assert len(results["first.pdf"]) == 1

    first = results["first.pdf"]["element1"]

    assert first["name"] == "Audit logs"
    assert len(first["requirements"]) == 2

    assert len(records) == 6

    assert (output_dir / "first-kdes.yaml").exists()
    assert (output_dir / "second-kdes.yaml").exists()


def test_save_llm_outputs(tmp_path):
    """Test that LLM records are saved in the required text format."""

    records = [
        {
            "llm_name": "google/gemma-3-1b-it",
            "prompt_used": "Identify the KDEs.",
            "prompt_type": "zero-shot",
            "llm_output": (
                "element1:\n"
                "  name: Audit logs\n"
                "  requirements:\n"
                "    - Audit logs must be enabled."
            ),
        }
    ]

    output_file = tmp_path / "llm_outputs.txt"

    result = save_llm_outputs(
        records,
        output_file=output_file,
    )

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "*LLM Name*" in content
    assert "google/gemma-3-1b-it" in content

    assert "*Prompt Used*" in content
    assert "Identify the KDEs." in content

    assert "*Prompt Type*" in content
    assert "zero-shot" in content

    assert "*LLM Output*" in content
    assert "Audit logs must be enabled." in content
