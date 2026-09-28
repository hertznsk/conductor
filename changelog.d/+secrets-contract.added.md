**Secret bindings contract**: workflows can now declare logical secret
requirements on executable script steps (`execution.secrets`) and MCP servers
(`runtime.mcp_servers.<name>.secrets`), which execution environment documents
bind to credential sources (`source.env`) and gate via optional `allow`
consumer policies. Resolved secrets are delivered via targeted environment
variables or HTTP headers and automatically sanitized across event streams,
checkpoints, logs, and diagnostics. Workflows and environments without secret
declarations continue to run with zero changes.
