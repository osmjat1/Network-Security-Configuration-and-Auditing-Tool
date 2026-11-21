
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = PROJECT_ROOT / "uploads"

ALLOWED_EXTENSIONS = {".txt", ".cfg", ".conf"}


def save_config(filename: str, content: bytes) -> Path:
    """Validate and save an uploaded network configuration."""

    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .txt, .cfg, and .conf files are allowed.")

    if not content:
        raise ValueError("The uploaded configuration is empty.")

    if len(content) > 2 * 1024 * 1024:
        raise ValueError("Configuration file must be 2 MB or smaller.")

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("File must contain valid UTF-8 text.") from exc

    if "\x00" in text:
        raise ValueError("Binary files are not supported.")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    # Use only the filename, never a user-supplied directory path.
    safe_name = Path(filename).name
    destination = UPLOAD_DIR / safe_name

    # Avoid silently overwriting an earlier upload.
    if destination.exists():
        stem = destination.stem
        suffix = destination.suffix
        number = 2

        while destination.exists():
            destination = UPLOAD_DIR / f"{stem}_{number}{suffix}"
            number += 1

    destination.write_text(text, encoding="utf-8")
    return destination

