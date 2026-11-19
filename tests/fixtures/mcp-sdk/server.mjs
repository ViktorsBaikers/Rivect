import { appendFileSync } from 'node:fs';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

const journal = process.argv[2];
const server = new Server({ name: 'fixture', version: '1' }, { capabilities: { tools: {} } });
const record = event => appendFileSync(journal, `${event}\n`);
record('started');
let initialized = false;
server.oninitialized = () => {
  initialized = true;
  record('initialized');
};
server.setRequestHandler(CallToolRequestSchema, ({ params }) => {
  if (!initialized) throw new McpError(ErrorCode.InvalidRequest, 'not initialized');
  record(params.name);
  switch (params.name) {
    case 'fixture.echo':
      return {
        content: [{ type: 'text', text: params.arguments.text }],
        structuredContent: { echo: params.arguments.text },
      };
    case 'fixture.fail':
      return { content: [{ type: 'text', text: 'private tool diagnostic' }], isError: true };
    default:
      throw new McpError(ErrorCode.InvalidParams, 'private protocol diagnostic');
  }
});
await server.connect(new StdioServerTransport());
