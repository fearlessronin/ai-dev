from __future__ import annotations

import re
from dataclasses import dataclass

from .models import AnalysisResult, CVEItem

AI_KEYWORDS = {
    "agent": 0.25,
    "agentic": 0.40,
    "llm": 0.30,
    "large language model": 0.40,
    "prompt injection": 0.60,
    "system prompt": 0.30,
    "tool calling": 0.45,
    "function calling": 0.45,
    "mcp": 0.35,
    "model context protocol": 0.50,
    "rag": 0.35,
    "vector database": 0.30,
    "langchain": 0.40,
    "crewai": 0.35,
    "autogen": 0.35,
    "llamaindex": 0.35,
    "openai": 0.20,
    "chatbot": 0.20,
    "plugin": 0.25,
}

CATEGORY_RULES = {
    "prompt_injection": ["prompt injection", "system prompt"],
    "unsafe_tool_execution": ["tool calling", "function calling", "plugin", "agent"],
    "data_exfiltration": ["rag", "vector database", "retrieval", "exfiltration"],
    "authz_or_isolation": ["tenant", "permission", "authorization", "sandbox", "escape"],
}


@dataclass
class RemediationPack:
    text: str
    snippets: dict[str, str]


def analyze_candidate(cve: CVEItem) -> AnalysisResult | None:
    haystack = f"{cve.description} {' '.join(cve.cwes)}".lower()

    matched: list[str] = []
    score = 0.0
    for keyword, weight in AI_KEYWORDS.items():
        if _contains_term(haystack, keyword):
            matched.append(keyword)
            score += weight

    if not matched:
        return None

    score = min(1.0, score)
    if score < 0.30:
        return None

    categories = _infer_categories(haystack)
    remediation = _remediation_for(categories)

    summary = (
        "Potential agentic AI vulnerability detected based on NVD description and keyword matching. "
        "Confirm exploitability in your deployment context and prioritize vendor patches."
    )

    return AnalysisResult(
        cve=cve,
        confidence=score,
        matched_keywords=sorted(set(matched)),
        categories=categories,
        summary=summary,
        remediation=remediation.text,
        code_examples=remediation.snippets,
    )


def _contains_term(text: str, term: str) -> bool:
    pattern = rf"\b{re.escape(term)}\b"
    return re.search(pattern, text) is not None


def _infer_categories(text: str) -> list[str]:
    categories: list[str] = []
    for category, terms in CATEGORY_RULES.items():
        if any(_contains_term(text, term) for term in terms):
            categories.append(category)

    if not categories:
        categories.append("general_ai_security")

    return categories


def _remediation_for(categories: list[str]) -> RemediationPack:
    if "prompt_injection" in categories:
        return RemediationPack(
            text=(
                "Treat all model output as untrusted. Add policy checks before tool calls, deny sensitive actions by "
                "default, and require explicit allowlisted intents."
            ),
            snippets={
                "python": """ALLOWED_TOOLS = {"search_docs", "read_ticket"}


def execute_tool(tool_name: str, args: dict):
    if tool_name not in ALLOWED_TOOLS:
        raise PermissionError(f"Tool '{tool_name}' is not allowlisted")
    return TOOL_REGISTRY[tool_name](**args)
""",
                "javascript": """const ALLOWED_TOOLS = new Set(["searchDocs", "readTicket"]);

export function executeTool(toolName, args) {
  if (!ALLOWED_TOOLS.has(toolName)) {
    throw new Error(`Tool ${toolName} is not allowlisted`);
  }
  return toolRegistry[toolName](args);
}
""",
            },
        )

    if "unsafe_tool_execution" in categories:
        return RemediationPack(
            text=(
                "Enforce strict argument schemas and authorization checks before any external side effect "
                "(file, network, shell, payments, admin APIs)."
            ),
            snippets={
                "python": """from pydantic import BaseModel


class SendEmailArgs(BaseModel):
    to: str
    subject: str
    body: str


def safe_send_email(raw_args: dict, user):
    if not user.can("send_email"):
        raise PermissionError("User lacks send_email permission")
    args = SendEmailArgs.model_validate(raw_args)
    return send_email(**args.model_dump())
""",
                "javascript": """import { z } from "zod";

const SendEmailArgs = z.object({
  to: z.string().email(),
  subject: z.string().min(1),
  body: z.string().min(1),
});

export function safeSendEmail(rawArgs, user) {
  if (!user.permissions.includes("send_email")) {
    throw new Error("Permission denied");
  }
  const args = SendEmailArgs.parse(rawArgs);
  return sendEmail(args);
}
""",
            },
        )

    return RemediationPack(
        text=(
            "Apply vendor patches, reduce agent privileges, isolate execution environments, "
            "monitor all model-driven actions with audit logs and anomaly alerts."
        ),
        snippets={
            "python": """# Principle of least privilege for agent credentials
AGENT_SCOPES = ["read:kb"]
agent_client = APIClient(scopes=AGENT_SCOPES)
""",
            "javascript": """// Principle of least privilege for agent credentials
const agentScopes = ["read:kb"];
const agentClient = new ApiClient({ scopes: agentScopes });
""",
        },
    )
