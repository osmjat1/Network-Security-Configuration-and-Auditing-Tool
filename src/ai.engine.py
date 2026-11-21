"""Central local LLM engine for NetSecureOps using Ollama."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 180


class AIEngineError(RuntimeError):
    """Raised when the local AI engine cannot complete a request."""


def generate(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
    options: dict[str, Any] | None = None,
    url: str = OLLAMA_URL,
    opener: Callable[..., Any] | None = None,
    response_format: str | None = None,
) -> str:
    """Generate text using the local Ollama API."""

    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("Prompt must be a non-empty string.")

    if not isinstance(model, str) or not model.strip():
        raise ValueError("Model must be a non-empty string.")

    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("Timeout must be a positive integer.")

    payload: dict[str, Any] = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": options or {"num_predict": 600},
    }

    if response_format:
        payload["format"] = response_format

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    send = opener or urllib.request.urlopen

    try:
        with send(request, timeout=timeout) as response:
            result = json.load(response)

    except urllib.error.HTTPError as exc:
        raise AIEngineError(
            f"Ollama returned HTTP error {exc.code}."
        ) from exc

    except urllib.error.URLError as exc:
        raise AIEngineError(
            "Cannot connect to Ollama. Check that the local service is running."
        ) from exc

    except TimeoutError as exc:
        raise AIEngineError(
            f"AI request timed out after {timeout} seconds."
        ) from exc

    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AIEngineError(
            "Ollama returned an invalid JSON response."
        ) from exc

    if not isinstance(result, dict):
        raise AIEngineError("Ollama response must be a JSON object.")

        if result.get("error"):
        raise AIEngineError(f"Ollama error: {result['error']}")

    answer = result.get("response")

    if not isinstance(answer, str) or not answer.strip():
        raise AIEngineError("Ollama returned an empty response.")

    if str(result.get("done_reason", "")).lower() == "length":
        raise AIEngineError("Ollama response was truncated.")

    return answer.strip()


def generate_json(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    timeout: int = DEFAULT_TIMEOUT,
    options: dict[str, Any] | None = None,
    url: str = OLLAMA_URL,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Generate and validate a JSON object using Ollama."""

    answer = generate(
        prompt,
        model=model,
        timeout=timeout,
        options=options,
        url=url,
        opener=opener,
        response_format="json",
    )

    try:
        result = json.loads(answer)
    except json.JSONDecodeError as exc:
        raise AIEngineError("AI did not return valid JSON.") from exc

    if not isinstance(result, dict):
        raise AIEngineError("AI JSON response must be an object.")

    return result
