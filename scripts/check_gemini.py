"""Check that the Gemini key and model work. Prints only a short reply, never the key.

Usage: uv run python -m scripts.check_gemini
"""

from __future__ import annotations

import sys

from google import genai

from core.config import get_settings


def main() -> int:
    settings = get_settings()
    client = genai.Client(api_key=settings.require_gemini_key())  # secret-scan: ignore
    try:
        response = client.models.generate_content(
            model=settings.gemini_model,
            contents="Reply with exactly the words: gateway ok",
        )
    except Exception as exc:  # noqa: BLE001 - report any provider error without the key
        print(f"FAILED: {type(exc).__name__}: {str(exc)[:300]}")
        return 1
    print(f"model={settings.gemini_model} reply={(response.text or '').strip()[:80]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
