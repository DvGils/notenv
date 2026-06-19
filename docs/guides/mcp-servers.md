# MCP servers

An MCP server is a tool your agent drives, and most of them need a credential: an
API key, a token. Today that credential lives in plaintext. You hardcode it in
`.mcp.json`, or you pull it from your shell with `${VAR}`, where it then sits in the
environment of every process the agent spawns. notenv moves it into your vault and
injects it into just that one server, at launch, masked, and never on disk.

## Inject a credential from notenv

Point the server's `command` at `notenv run` and let it launch the real server:

```json
{
  "mcpServers": {
    "brave-search": {
      "command": "notenv",
      "args": ["run", "--only", "BRAVE_API_KEY", "--",
               "npx", "-y", "@brave/brave-search-mcp-server", "--transport", "stdio"]
    }
  }
}
```

When your agent starts the server, notenv unlocks your vault, injects `BRAVE_API_KEY`
into the server's environment, and execs it. The value is decrypted at launch, never
written into `.mcp.json` or your shell, and masked if the server ever prints or logs it.

`--only` narrows the injection to the named key, so a server gets
exactly its own credential and nothing else in the namespace. The pattern is the same
for any stdio server that reads its credential from the environment; only the launch
command and the key name change.

For a server you run in a container, inject the key and let the container inherit it:

```json
"args": ["run", "--only", "API_KEY", "--",
         "docker", "run", "-i", "--rm", "-e", "API_KEY", "example/some-mcp-server"]
```

The bare `-e API_KEY` (a name, no value) tells docker to pass the variable through
from the environment notenv built.

## Scope every server under a handoff

The pattern above keeps a credential off disk, but each server still runs against your
real vault. Hand the whole agent a scoped session instead, and every server it spawns
inherits the scope:

```sh
notenv handoff -- claude
```

This is the combination worth reaching for: the agent holds no master key, and each
server pulls only the one credential it needs from a vault that disappears at the end of the session. See [Agent handoff](../concepts/agent-handoff.md) for more info.

## What this covers

This works for **stdio** MCP servers that read their credential from the environment,
which is most local servers, because the launch command is yours to wrap.

It does not cover **remote (HTTP) MCP servers**, the kind reached by URL with OAuth.
There is no launch command to wrap and no environment credential to inject, so point
those at their own authentication.

!!! warning "Same trust model as handoff"

    notenv scopes what a server can decrypt and masks the values it injects. It does not
    sandbox the server or stop it from sending a value onward: a tool holding a secret can
    transmit it anywhere it reaches. Wrap only servers you trust, and use the OS (a
    sandbox, egress rules) to contain what they do. See [Agent handoff](../concepts/agent-handoff.md).

---

**See also:** [AI agents](ai-agents.md) ·
[Agent handoff](../concepts/agent-handoff.md) ·
[Environment variables](../reference/environment.md)
