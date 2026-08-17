# LangChain Go starter template

This command gives you a minimal LangChain Go starting point for tool-calling workflows in the backend module.

## What it includes

- OpenAI-compatible model setup using repository-friendly `AI_*` environment variables
- A simple tool registry with JSON-schema tool definitions
- A tool-call loop that executes model-requested tools and feeds results back into the conversation
- Safe starter tools you can replace with your own internal automation

## Run it

```bash
cd /home/runner/work/auto-bughunter/auto-bughunter/backend
export AI_API_KEY=your-key
export AI_MODEL=gpt-4o-mini
go run ./cmd/langchain-template -prompt "Use the tools and suggest the next custom capability to add."
```

If you are using an OpenAI-compatible gateway, also set `AI_API_BASE`.

## Inspect the starter tools

```bash
cd /home/runner/work/auto-bughunter/auto-bughunter/backend
go run ./cmd/langchain-template -list-tools
```

## Customize it

1. Replace the sample entries in `starterTools()` with your own tool definitions.
2. Extend the JSON schemas so the model knows which arguments each tool expects.
3. Swap the prompt defaults to match your workflow.
4. Add tests for each tool handler before expanding the template further.
