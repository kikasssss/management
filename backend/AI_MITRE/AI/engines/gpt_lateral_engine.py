# AI_MITRE/AI/engines/gpt_lateral_engine.py

import json
from typing import Dict, Any, Optional
from AI_MITRE.AI.clients.openai_responses_client import OpenAIResponsesClient
from AI_MITRE.AI.prompts.gpt_lateral_prompt import LATERAL_CORRELATION_INSTRUCTIONS
from AI_MITRE.AI.engines.gpt_correlation_engine import _validate_result


class GPTLateralCorrelationEngine:
    def __init__(self, client: Optional[OpenAIResponsesClient] = None) -> None:
        self.client = client or OpenAIResponsesClient()

    def correlate_lateral_context(
        self,
        lateral_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Input: actor-centric lateral_context
        Output: validated JSON reasoning result
        """

        user_input = {
            "lateral_context": lateral_context
        }

        user_text = (
            "The following input is provided in JSON format.\n"
            "You must return a valid JSON object as output.\n\n"
            + json.dumps(user_input, ensure_ascii=False)
        )

        result = self.client.create_json_response(
            instructions=LATERAL_CORRELATION_INSTRUCTIONS,
            user_input=user_text,
            max_output_tokens=1200,
        )

        return _validate_result(result)
