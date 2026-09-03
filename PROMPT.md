# PROMPTS

## zero-shot

```text
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

R001 | CIS-ID 1.1.1 | Ensure example security setting is enabled (Automated)
```

## few-shot

```text
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

R001 | CIS-ID 1.1.1 | Ensure example security setting is enabled (Automated)
```

## chain-of-thought

```text
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

Perform that reasoning internally. Do not show the reasoning.

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

R001 | CIS-ID 1.1.1 | Ensure example security setting is enabled (Automated)
```
