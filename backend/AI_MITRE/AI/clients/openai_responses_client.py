import os
import json
import time
from typing import Any, Dict, Optional, Tuple, List

import requests


OPENAI_API_BASE = "https://api.openai.com/v1"
RESPONSES_ENDPOINT = f"{OPENAI_API_BASE}/responses"


class OpenAIResponsesClient:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: int = 60,
        max_retries: int = 2,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise RuntimeError("Missing OPENAI_API_KEY environment variable")

        self.model = model or os.getenv("OPENAI_MODEL", "gpt-5-mini")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _extract_text(self, resp_json: Dict[str, Any]) -> str:
        """
        Robust extractor for Responses API.
        Tries multiple locations to retrieve JSON output safely.
        """

        # 1️⃣ Best case: API already parsed JSON for us
        if "output_parsed" in resp_json and resp_json["output_parsed"]:
            # output_parsed is already a dict
            return json.dumps(resp_json["output_parsed"], ensure_ascii=False)

        # 2️⃣ Scan output[].content[].text
        chunks = []
        for item in resp_json.get("output", []):
            for content in item.get("content", []):
                if isinstance(content, dict) and "text" in content:
                    chunks.append(content["text"])

        if chunks:
            return "\n".join(chunks).strip()

        # 3️⃣ Last resort: stringify entire response for debugging
        raise RuntimeError(
            "OpenAI response does not contain JSON text.\n"
            f"Raw response: {json.dumps(resp_json, indent=2)}"
        )

    def create_json_response(
        self,
        *,
        instructions: str,
        user_input: str,
        max_output_tokens: int = 1200,
    ) -> Dict[str, Any]:
        """
        Robust JSON-mode handler for OpenAI Responses API.
        Priority:
        1) output_parsed (if present)
        2) output_text -> json.loads
        """

        user_text = (
            "The following input is provided in JSON format.\n"
            "You MUST return a valid JSON object only.\n\n"
            f"{user_input}"
        )

        payload = {
            "model": self.model,
            "instructions": instructions,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": user_text}],
                }
            ],
            "max_output_tokens": max_output_tokens,
            "text": {"format": {"type": "json_object"}},
            "reasoning": {"effort": "low"},
            "store": False,
        }

        last_err = None

        for attempt in range(self.max_retries + 1):
            try:
                r = requests.post(
                    RESPONSES_ENDPOINT,
                    headers=self._headers(),
                    data=json.dumps(payload),
                    timeout=self.timeout_seconds,
                )

                if r.status_code >= 400:
                    raise RuntimeError(
                        f"OpenAI API error {r.status_code}: {r.text}"
                    )

                resp_json = r.json()

                # ✅ 1. Preferred: output_parsed
                if resp_json.get("output_parsed") is not None:
                    return resp_json["output_parsed"]

                # ✅ 2. Fallback: parse output_text
                texts = []
                for item in resp_json.get("output", []):
                    for content in item.get("content", []):
                        if content.get("type") in ("output_text", "text"):
                            texts.append(content.get("text", ""))

                combined = "\n".join(texts).strip()
                if not combined:
                    raise RuntimeError(
                        "Model returned no text output.\n"
                        f"Raw response: {json.dumps(resp_json, indent=2)}"
                    )

                try:
                    return json.loads(combined)
                except json.JSONDecodeError as e:
                    raise RuntimeError(
                        "Model returned text but not valid JSON.\n"
                        f"Text:\n{combined}\n\n"
                        f"Raw response:\n{json.dumps(resp_json, indent=2)}"
                    ) from e

            except Exception as e:
                last_err = e
                if attempt < self.max_retries:
                    time.sleep(0.6 * (attempt + 1))
                    continue
                raise

        raise last_err
