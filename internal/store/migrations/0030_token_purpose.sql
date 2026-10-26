-- What a user's token is for: 'mcp' (the MCP endpoint, as every token was
-- before) or 'threats' (the threat list's REST API, docs/threats.md). Each
-- works only on its own endpoints.
ALTER TABLE mcp_tokens ADD COLUMN purpose TEXT NOT NULL DEFAULT 'mcp' CHECK (purpose IN ('mcp', 'threats'));
