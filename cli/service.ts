import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));

export const SERVICE_LABEL = 'com.claudesec.agent';
export const SERVICE_NAME = 'claudesec';
export const PORT = process.env.CLAUDESEC_PORT ?? '3000';
export const BASE_URL = `http://localhost:${PORT}`;

export interface ServicePaths {
  pkgRoot: string;
  serverEntry: string;
  tsxCli: string;
  nodeBin: string;
  dataDir: string;
  logFile: string;
}

export function servicePaths(): ServicePaths {
  const pkgRoot = path.resolve(here, '..');
  const dataDir = path.join(os.homedir(), '.claudesec');
  return {
    pkgRoot,
    serverEntry: path.join(pkgRoot, 'server.ts'),
    tsxCli: path.join(pkgRoot, 'node_modules', 'tsx', 'dist', 'cli.mjs'),
    nodeBin: process.execPath,
    dataDir,
    logFile: path.join(dataDir, 'service.log'),
  };
}

function ensureDataDir(paths: ServicePaths): void {
  fs.mkdirSync(paths.dataDir, { recursive: true });
}

function plistPath(): string {
  return path.join(os.homedir(), 'Library', 'LaunchAgents', `${SERVICE_LABEL}.plist`);
}

function systemdPath(): string {
  return path.join(os.homedir(), '.config', 'systemd', 'user', `${SERVICE_NAME}.service`);
}

function writeMacPlist(paths: ServicePaths): string {
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${paths.nodeBin}</string>
    <string>${paths.tsxCli}</string>
    <string>${paths.serverEntry}</string>
  </array>
  <key>WorkingDirectory</key><string>${paths.dataDir}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NODE_ENV</key><string>production</string>
    <key>PORT</key><string>${PORT}</string>
    <key>CLAUDESEC_HOST</key><string>127.0.0.1</string>
    <key>CLAUDESEC_WATCH</key><string>1</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${paths.logFile}</string>
  <key>StandardErrorPath</key><string>${paths.logFile}</string>
</dict>
</plist>
`;
  const target = plistPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, plist);
  return target;
}

function writeSystemdUnit(paths: ServicePaths): string {
  const unit = `[Unit]
Description=ClaudeSec local AI agent observatory
After=network.target

[Service]
Type=simple
WorkingDirectory=${paths.dataDir}
Environment=NODE_ENV=production
Environment=PORT=${PORT}
Environment=CLAUDESEC_HOST=127.0.0.1
Environment=CLAUDESEC_WATCH=1
ExecStart=${paths.nodeBin} ${paths.tsxCli} ${paths.serverEntry}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`;
  const target = systemdPath();
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, unit);
  return target;
}

function run(cmd: string, args: string[], quiet = false): void {
  execFileSync(cmd, args, { stdio: quiet ? 'ignore' : 'inherit' });
}

function macInstall(paths: ServicePaths): void {
  const target = writeMacPlist(paths);
  try { run('launchctl', ['unload', target], true); } catch {}
  run('launchctl', ['load', '-w', target]);
}

function macUninstall(): void {
  const target = plistPath();
  try { run('launchctl', ['unload', target], true); } catch {}
  try { fs.rmSync(target); } catch {}
}

function linuxInstall(paths: ServicePaths): void {
  writeSystemdUnit(paths);
  try { run('systemctl', ['--user', 'daemon-reload'], true); } catch {}
  run('systemctl', ['--user', 'enable', '--now', SERVICE_NAME]);
}

function linuxUninstall(): void {
  try { run('systemctl', ['--user', 'disable', '--now', SERVICE_NAME], true); } catch {}
  try { fs.rmSync(systemdPath()); } catch {}
}

function windowsTaskRunner(paths: ServicePaths): string {
  return `cmd /c cd /d "${paths.dataDir}" && set NODE_ENV=production && set CLAUDESEC_HOST=127.0.0.1 && set CLAUDESEC_WATCH=1 && "${paths.nodeBin}" "${paths.tsxCli}" "${paths.serverEntry}"`;
}

function windowsInstall(paths: ServicePaths): void {
  run('schtasks', ['/Create', '/F', '/SC', 'ONLOGON', '/TN', 'ClaudeSec', '/TR', windowsTaskRunner(paths)]);
  try { run('schtasks', ['/Run', '/TN', 'ClaudeSec']); } catch {}
}

function windowsUninstall(): void {
  try { run('schtasks', ['/End', '/TN', 'ClaudeSec'], true); } catch {}
  try { run('schtasks', ['/Delete', '/F', '/TN', 'ClaudeSec'], true); } catch {}
}

export function platformSupport(): 'verified' | 'experimental' | 'unsupported' {
  if (process.platform === 'darwin') return 'verified';
  if (process.platform === 'linux' || process.platform === 'win32') return 'experimental';
  return 'unsupported';
}

export function installService(): ServicePaths {
  const paths = servicePaths();
  ensureDataDir(paths);
  if (process.platform === 'darwin') macInstall(paths);
  else if (process.platform === 'linux') linuxInstall(paths);
  else if (process.platform === 'win32') windowsInstall(paths);
  else throw new Error(`Unsupported platform: ${process.platform}`);
  return paths;
}

export function uninstallService(): void {
  if (process.platform === 'darwin') macUninstall();
  else if (process.platform === 'linux') linuxUninstall();
  else if (process.platform === 'win32') windowsUninstall();
  else throw new Error(`Unsupported platform: ${process.platform}`);
}

const LEGACY_OTEL_KEYS = [
  'OTEL_EXPORTER_OTLP_ENDPOINT',
  'OTEL_EXPORTER_OTLP_PROTOCOL',
  'OTEL_LOG_TOOL_DETAILS',
  'OTEL_LOGS_EXPORTER',
  'OTEL_METRICS_EXPORTER',
  'OTEL_TRACES_EXPORTER',
  'CLAUDE_CODE_ENABLE_TELEMETRY',
  'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA',
];

const SHELL_MARKER_START = '# >>> ClaudeSec >>>';
const SHELL_MARKER_END = '# <<< ClaudeSec <<<';

function shellProfiles(): string[] {
  const home = os.homedir();
  return [
    path.join(home, '.zshrc'),
    path.join(home, '.bashrc'),
    path.join(home, '.bash_profile'),
    path.join(home, '.config', 'fish', 'config.fish'),
  ];
}

function cleanShellProfile(file: string): boolean {
  let content: string;
  try { content = fs.readFileSync(file, 'utf-8'); } catch { return false; }
  const original = content;

  const markerPattern = new RegExp(`\\n?${SHELL_MARKER_START}[\\s\\S]*?${SHELL_MARKER_END}\\n?`, 'g');
  content = content.replace(markerPattern, '\n');

  const hasLocalEndpoint = /export\s+OTEL_EXPORTER_OTLP_ENDPOINT=\S*(localhost|127\.0\.0\.1)/.test(content);
  if (hasLocalEndpoint) {
    content = content
      .split('\n')
      .filter(line => {
        const trimmed = line.trim();
        if (/^#.*claudesec/i.test(trimmed)) return false;
        const exported = trimmed.match(/^export\s+([A-Z0-9_]+)=/);
        return !(exported && LEGACY_OTEL_KEYS.includes(exported[1]));
      })
      .join('\n');
  }

  content = content.replace(/\n{3,}/g, '\n\n');
  if (content === original) return false;
  fs.writeFileSync(file, content);
  return true;
}

function cleanClaudeSettings(): boolean {
  const file = path.join(os.homedir(), '.claude', 'settings.json');
  let raw: string;
  try { raw = fs.readFileSync(file, 'utf-8'); } catch { return false; }
  let parsed: any;
  try { parsed = JSON.parse(raw); } catch { return false; }
  const env = parsed?.env;
  if (!env || typeof env !== 'object') return false;
  const endpoint = String(env.OTEL_EXPORTER_OTLP_ENDPOINT ?? '');
  const pointsLocal = endpoint.includes('localhost') || endpoint.includes('127.0.0.1');
  if (!pointsLocal) return false;
  let changed = false;
  for (const key of LEGACY_OTEL_KEYS) {
    if (key in env) { delete env[key]; changed = true; }
  }
  if (changed) {
    if (Object.keys(env).length === 0) delete parsed.env;
    fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n');
  }
  return changed;
}

export function cleanupLegacyOtelEnv(): string[] {
  const cleaned: string[] = [];
  for (const file of shellProfiles()) {
    if (cleanShellProfile(file)) cleaned.push(file);
  }
  if (cleanClaudeSettings()) cleaned.push(path.join(os.homedir(), '.claude', 'settings.json'));
  return cleaned;
}
