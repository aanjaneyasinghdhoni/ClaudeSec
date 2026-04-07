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
      { key: 'CLAUDE_CODE_ENABLE_TELEMETRY', value: '1', description: 'Enable telemetry' },
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /claude/i,
    spanAttributes: ['gen_ai.tool.name', 'gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens'],
    docsUrl: 'https://docs.anthropic.com/claude/docs/claude-code',
  },
  {
    id: 'github-copilot',
    name: 'GitHub Copilot CLI',
    color: '#6366f1',
    description: 'GitHub\'s AI pair programmer and CLI agent.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /copilot/i,
    spanAttributes: ['gen_ai.tool.name', 'github.copilot.model'],
    docsUrl: 'https://docs.github.com/en/copilot',
  },
  {
    id: 'openhands',
    name: 'OpenHands',
    color: '#22c55e',
    description: 'Open-source autonomous software engineering agent (formerly OpenDevin).',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /openhands|opendevin/i,
    spanAttributes: ['gen_ai.tool.name', 'openhands.agent_type'],
    docsUrl: 'https://docs.all-hands.dev',
  },
  {
    id: 'cursor',
    name: 'Cursor',
    color: '#a855f7',
    description: 'AI-first code editor with agentic capabilities.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /cursor/i,
    spanAttributes: ['gen_ai.tool.name'],
    docsUrl: 'https://cursor.com/docs',
  },
  {
    id: 'aider',
    name: 'Aider',
    color: '#ec4899',
    description: 'AI pair programming in your terminal.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /aider/i,
    spanAttributes: ['aider.model', 'aider.edit_format'],
    docsUrl: 'https://aider.chat/docs',
  },
  {
    id: 'cline',
    name: 'Cline',
    color: '#14b8a6',
    description: 'Autonomous coding agent for VS Code.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /cline/i,
    spanAttributes: ['gen_ai.tool.name', 'cline.task_id'],
    docsUrl: 'https://github.com/cline/cline',
  },
  {
    id: 'goose',
    name: 'Goose',
    color: '#f59e0b',
    description: 'Block\'s open-source AI developer agent.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /goose/i,
    spanAttributes: ['gen_ai.tool.name', 'goose.session_id'],
    docsUrl: 'https://block.github.io/goose',
  },
  {
    id: 'continue',
    name: 'Continue.dev',
    color: '#0ea5e9',
    description: 'Open-source AI code assistant for VS Code and JetBrains.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /continue/i,
    spanAttributes: ['gen_ai.tool.name'],
    docsUrl: 'https://docs.continue.dev',
  },
  {
    id: 'windsurf',
    name: 'Windsurf',
    color: '#38bdf8',
    description: 'Codeium\'s agentic IDE with Cascade AI.',
    envVars: [
      { key: 'OTEL_EXPORTER_OTLP_ENDPOINT', value: '{{ENDPOINT}}', description: 'OTLP collector URL' },
      { key: 'OTEL_EXPORTER_OTLP_PROTOCOL', value: 'http/json', description: 'Protocol' },
    ],
    serviceNamePattern: /windsurf|codeium/i,
    spanAttributes: ['gen_ai.tool.name', 'windsurf.session_id'],
    docsUrl: 'https://docs.codeium.com/windsurf',
  },
  {
    id: 'unknown',
    name: 'Unknown Agent',
    color: '#64748b',
    description: 'Any agent emitting standard OTLP traces.',
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
