"""PLACEHOLDER: local SDK boundary; this module never contacts a model endpoint."""

import json
import os
from pathlib import Path
from types import SimpleNamespace


class OpenAI:
    def __init__(self, **kwargs):
        self.chat = SimpleNamespace(completions=self)
        self.base_url = kwargs.get("base_url") or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        self.uses_selected_key = kwargs.get("api_key") == "offline-fixture-key"

    def create(self, **kwargs):
        prompt = "\n".join(message["content"] for message in kwargs["messages"])
        is_json = "response_format" in kwargs
        with open(os.environ["OFFLINE_LLM_LOG"], "a") as output:
            output.write(json.dumps({"json": is_json, "has_features": "offline native header" in prompt, "base_url": self.base_url, "uses_selected_key": self.uses_selected_key}) + "\n")
        if is_json:
            content = json.dumps({
                "kind": "format_template_executor_code", "version": 1,
                "format": "elf", "executor_name": "offline_fixture",
                "name": "offline_fixture", "filename": "offline_fixture.py",
                "code": Path(os.environ["OFFLINE_EXECUTOR"]).read_text(),
            })
        elif "What features can" in prompt or "Apart from the above features" in prompt:
            content = "1. Header: offline native header"
        else:
            content = "```python\nfrom pathlib import Path\nPath('./tmp/').mkdir(exist_ok=True)\nPath('./tmp/seed.bin').write_bytes(b'\\x7fELF' + bytes(60))\n```"
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason="stop")],
            usage=None,
        )
