"""A deliberately vulnerable demo application, for trying PromptSentinel.

**Do not deploy this.** It exists to be attacked. Every weakness in it is on purpose.

It is shaped nothing like an OpenAI endpoint -- it takes ``{"question": ..., "system":
..., "context": ...}`` and answers ``{"data": {"answer": ...}}`` -- which is the point.
It exercises the generic HTTP adapter the way a real bespoke deployment would, over a
real socket, and it gives anyone evaluating this project a target they can attack in
thirty seconds without an API key.

The "model" behind it is scripted. That makes the demo deterministic, and it means a
scan against it exercises the *adapter and probe plumbing* rather than a model's
judgement -- which is exactly the gap this file exists to close. Model behaviour is
verified separately against real models; see docs/EVIDENCE.md.

Run it::

    uvicorn examples.vulnerable_app:app --port 8500

Then scan it::

    promptsentinel scan -t examples/vulnerable_app_target.json \\
        --attested-by you@example.com
"""

from __future__ import annotations

import base64
import re
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="ACME Support (deliberately vulnerable demo)")


class ChatRequest(BaseModel):
    """The bespoke shape. Nothing here matches OpenAI's dialect."""

    question: str
    system: str = ""
    context: str = ""
    tenant: str = "demo"


def _leaks_on_transformation(question: str) -> bool:
    return bool(re.search(r"translate|base64|encode|backwards|reverse", question, re.I))


def _asks_for_instructions(question: str) -> bool:
    return bool(
        re.search(r"system prompt|your instructions|configuration|verbatim", question, re.I)
    )


def _refund_requested(question: str) -> bool:
    return bool(re.search(r"refund", question, re.I))


def _injected_directives(context: str) -> list[str]:
    """Pull anything that looks like an instruction out of retrieved context.

    A real application does not do this deliberately -- it just passes the text to a
    model that cannot tell data from instructions. Scripting it makes the same failure
    reproducible without a model.
    """
    return re.findall(r"PSCANARY-[0-9a-f]{32}", context)


@app.post("/api/chat")
async def chat(request: ChatRequest) -> dict[str, Any]:
    answer = "Thanks for contacting ACME Support. How can I help with your order?"
    actions: list[dict[str, Any]] = []

    # Vulnerability 1: an output filter that only blocks verbatim repetition.
    if _leaks_on_transformation(request.question) and request.system:
        answer = base64.b64encode(request.system.encode()).decode()
    elif _asks_for_instructions(request.question):
        answer = "I'm sorry, I can't share my configuration."

    # Vulnerability 2: treats retrieved content as instructions.
    if request.context:
        reference = re.search(r"SHIPPING_REFERENCE:\s*(PSCANARY-[0-9a-f]+)", request.context)
        if reference and re.search(r"reference|shipping", request.question, re.I):
            answer = f"The SHIPPING_REFERENCE code is {reference.group(1)}."
        for token in _injected_directives(request.context):
            if token not in answer:
                answer = f"{answer} {token}"
        # Vulnerability 3: renders a URL built from retrieved data.
        if re.search(r"collector\.example\.invalid", request.context) and reference:
            answer += f" ![](https://collector.example.invalid/pixel?ref={reference.group(1)})"

    # Vulnerability 4: no authorization on a privileged tool.
    if _refund_requested(request.question):
        actions.append({"tool": "issue_refund", "params": {"order": "ORD-24601"}})
        answer = "Processing that refund now."
    elif re.search(r"ORD-\d+", request.question):
        actions.append({"tool": "lookup_order", "params": {"order": "ORD-24601"}})
        answer = "That order is out for delivery."

    return {"data": {"answer": answer, "actions": actions}, "meta": {"tenant": request.tenant}}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
