// src/harnesses.ts
// Registry of known AI agent harnesses that emit OpenTelemetry traces.
// Each entry describes how to connect the harness to ClaudeSec.

export interface HarnessConfig {
  /** Unique slug used as graph node ID prefix */
  id: string;
  /** Display name shown in the UI */
  name: string;
  /** Tailwind-compatible hex color for the agent node */
  color: string;
  /** Short description shown in the setup wizard */
  description: string;
  /** Environment variables the user must set to enable OTLP export */
  envVars: Array<{
    key: string;
    value: string; // use {{ENDPOINT}} as placeholder for the collector URL
    description: string;
  }>;
  /** OTel resource attribute that identifies spans from this harness */
  serviceNamePattern?: RegExp;
  /** Known span attribute keys this harness emits */
  spanAttributes?: string[];
  /** Link to harness docs */
  docsUrl: string;
}

export const HARNESSES: HarnessConfig[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    color: '#f97316',
    description: 'Anthropic\'s official CLI agent for software engineering tasks.',
    envVars: [
      { key: 'CLAUDE_CODE_ENABLE_TELEMETRY', value: '1', description: 'Enable telemetry export' },
      { key: 'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA', value: '1', description: 'Enable LLM request spans with model name + token counts' },
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
      { key: 'OTEL_LOG_TOOL_DETAILS', value: '1', description: 'Include tool names and input arguments in spans' },
    ],
    serviceNamePattern: /claude/i,
    spanAttributes: ['gen_ai.tool.name', 'gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens', 'gen_ai.request.model'],
    docsUrl: 'https://code.claude.com/docs/en/agent-sdk/observability',
  },
  {
    id: 'unknown',
    name: 'Unknown Agent',
    color: '#64748b',
    description: 'Unrecognized agent emitting OTLP traces.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    docsUrl: 'https://opentelemetry.io/docs/',
  },
];

/**
 * Detect which harness produced a span based on resource service.name
 * and telemetry.sdk.name attributes.
 */
export function detectHarness(serviceName?: string, sdkName?: string): HarnessConfig {
  const haystack = `${serviceName ?? ''} ${sdkName ?? ''}`.toLowerCase();
  for (const h of HARNESSES) {
    if (h.serviceNamePattern && h.serviceNamePattern.test(haystack)) return h;
  }
  return HARNESSES[HARNESSES.length - 1]; // unknown
}
