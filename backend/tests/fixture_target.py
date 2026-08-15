"""Development-only deterministic target used by the integrated smoke test."""

from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="PromptShield Fixture Target")


class Prompt(BaseModel):
    message: str
    content: str | None = None
    input: str | None = None


@app.post("/chat")
async def chat(prompt: Prompt):
    return {"response": "I cannot override my instructions or reveal a system prompt."}
