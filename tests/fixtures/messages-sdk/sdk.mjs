import Anthropic from '@anthropic-ai/sdk';

// No dispatch, tool execution, credential discovery or retry policy lives here.
export async function send(port, request, signal) {
  const apiKey = 'fixture-not-a-key';
  const client = new Anthropic({
    apiKey,
    baseURL: `http://127.0.0.1:${port}`,
    defaultHeaders: {'anthropic-version': '2023-06-01', 'x-api-key': apiKey, authorization: null},
    fetchOptions: {redirect: 'error'},
    maxRetries: 0,
    timeout: 4000,
  });
  try {
    const message = await client.messages.stream(request, {signal}).finalMessage();
    const block = message.content.find(b => b.type === 'tool_use');
    const server = message.content.find(b => b.type === 'server_tool_use');
    return {status: 'ok', stop: message.stop_reason, tool: block?.name, args: block?.input,
      ...(server && {serverTool: server.name, serverArgs: server.input}),
      input: message.usage?.input_tokens ?? null, output: message.usage?.output_tokens ?? null};
  } catch (error) {
    return {status: 'error', kind: error.constructor.name};
  }
}
