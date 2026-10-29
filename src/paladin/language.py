"""English technical-text contract; no translation or language auto-detection."""

TEXT_POLICY = "english-ascii-v1"


def require_english(text):
    """Accept printable ASCII and ordinary whitespace for English technical text.

    This deterministic character contract rejects unsupported scripts. It cannot
    distinguish English from other languages written with ASCII characters.
    """
    if not isinstance(text, str) or any(not (32 <= ord(c) <= 126 or c in "\t\n\r") for c in text):
        raise ValueError("English-only text required: use printable ASCII, tabs and line breaks")
    return text


def validate_authored_text(value):
    """Validate structured pack text, retaining upstream affected metadata verbatim."""
    if isinstance(value, str):
        require_english(value)
    elif isinstance(value, list):
        for item in value:
            validate_authored_text(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            require_english(key)
            if key != "source_affected":
                validate_authored_text(item)
