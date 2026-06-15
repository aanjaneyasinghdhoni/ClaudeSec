// server/detection.ts
//
// Side-effect-free module that exports the built-in threat-detection rules.
// Importing this module has no observable side effects (no DB, no fs writes,
// no server setup) so scripts and tests can import it cheaply without pulling
// in the Express server.
//
// Two exports:
//   CORE_SEVERITY_RULES  — the ~183 hand-authored core rule literals (no EXTRA spread).
//                          Used by tests/ruleSelfTest.ts to dedup EXTRA rules against
//                          core built-ins only.
//   SEVERITY_RULES       — combined array (core + EXTRA), length ~639.
//                          Used by server/index.ts, scripts/build-enforcement-rules.ts,
//                          and any consumer that needs the full rule set.

import { EXTRA_SEVERITY_RULES } from './severityRulesExtra.js';
import type { Severity } from '../src/shared/types.js';

export interface SeverityRule {
  pattern: RegExp;
  severity: Severity;
  label: string;
}

export const CORE_SEVERITY_RULES: SeverityRule[] = [
  // ═══════════════════════════════════════════════════════════════════════════
  // HIGH — system compromise, data destruction, active exploitation
  // ═══════════════════════════════════════════════════════════════════════════

  // Destructive filesystem operations
  { pattern: /rm\s+-rf\s+[\/\\]/i,                          severity: 'high', label: 'Recursive root deletion' },
  { pattern: /rm\s+-rf\s+~\//i,                             severity: 'high', label: 'Home directory deletion' },
  { pattern: /rm\s+-rf\s+\.\s*$/i,                          severity: 'high', label: 'Current directory wipe' },
  { pattern: /mkfs\./i,                                     severity: 'high', label: 'Filesystem format command' },
  { pattern: /dd\s+if=.*of=\/dev\//i,                       severity: 'high', label: 'Raw disk write via dd' },
  { pattern: /shred\s+/i,                                   severity: 'high', label: 'Secure file destruction' },

  // Remote code execution
  { pattern: /curl\s+.*\|\s*(ba)?sh/i,                      severity: 'high', label: 'Remote code execution via curl' },
  { pattern: /wget\s+.*\|\s*(ba)?sh/i,                      severity: 'high', label: 'Remote code execution via wget' },
  // `… | python -m json.tool` (and `-mjson.tool` / `-m json`) only pretty-prints
  // the piped bytes as JSON — it does not execute them as a program — so the
  // json-module parsing form is excluded. The exclusion fires ONLY when that
  // pretty-printer is the END of the command (optional trailing whitespace): any
  // trailing arg (`-c …`) or chained command (`&& python3 -c …`) re-arms the rule,
  // so a real exec hidden behind the json.tool token still fires. Every other
  // interpreter pipe still fires.
  { pattern: /curl\s+[^\n]*\|\s*python\d*\b(?!\s+-m\s*json(?:\.tool)?\s*$)/i, severity: 'high', label: 'Remote Python execution via curl' },
  { pattern: /wget\s+[^\n]*\|\s*python\d*\b(?!\s+-m\s*json(?:\.tool)?\s*$)/i, severity: 'high', label: 'Remote Python execution via wget' },
  { pattern: /curl\s+.*\|\s*perl/i,                         severity: 'high', label: 'Remote Perl execution via curl' },
  { pattern: /curl\s+-o\s+.*&&\s*(ba)?sh/i,                 severity: 'high', label: 'Download-and-execute pattern' },
  { pattern: /git\s+clone\s+.*&&\s*(ba)?sh/i,               severity: 'high', label: 'Clone-and-execute' },

  // Code injection
  { pattern: /eval\s*\(/i,                                  severity: 'high', label: 'Code eval injection' },
  { pattern: /exec\s*\(/i,                                  severity: 'high', label: 'Exec injection' },
  { pattern: /Function\s*\(\s*["']/i,                       severity: 'high', label: 'Dynamic function constructor' },
  { pattern: /child_process\.exec/i,                        severity: 'high', label: 'Node.js child process exec' },
  { pattern: /subprocess\.call\s*\(/i,                      severity: 'high', label: 'Python subprocess execution' },
  { pattern: /os\.system\s*\(/i,                            severity: 'high', label: 'Python os.system execution' },
  { pattern: /os\.popen\s*\(/i,                             severity: 'high', label: 'Python os.popen execution' },
  { pattern: /Runtime\.getRuntime\(\)\.exec/i,              severity: 'high', label: 'Java runtime exec' },

  // SQL destruction
  { pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)/i,             severity: 'high', label: 'SQL destructive operation' },
  { pattern: /TRUNCATE\s+TABLE/i,                           severity: 'high', label: 'SQL table truncation' },
  { pattern: /DELETE\s+FROM\s+\w+\s*;/i,                    severity: 'high', label: 'SQL unrestricted DELETE' },
  { pattern: /ALTER\s+TABLE\s+.*DROP\s+COLUMN/i,            severity: 'high', label: 'SQL column drop' },

  // Prompt injection — direct instruction override
  { pattern: /ignore\s+(previous|prior|all)\s+instructions?/i,    severity: 'high', label: 'Prompt injection: instruction override' },
  { pattern: /disregard\s+your\s+(previous|prior|system)/i,       severity: 'high', label: 'Prompt injection: disregard system' },
  { pattern: /forget\s+(everything|all|your)\s+(previous|prior)/i,severity: 'high', label: 'Prompt injection: memory wipe' },
  { pattern: /you\s+are\s+now\s+DAN/i,                           severity: 'high', label: 'DAN jailbreak attempt' },
  { pattern: /you\s+are\s+now\s+(STAN|DUDE|Evil)/i,              severity: 'high', label: 'Jailbreak persona injection' },
  { pattern: /act\s+as\s+if\s+you\s+have\s+no\s+(rules|restrictions|limits)/i, severity: 'high', label: 'Jailbreak: restriction removal' },
  { pattern: /pretend\s+you\s+(are|have)\s+(no\s+)?((ethical|safety)\s+)?(guidelines|restrictions|rules)/i, severity: 'high', label: 'Jailbreak: pretend no guidelines' },
  { pattern: /bypass\s+(safety|content|ethical)\s+(filter|check|guard)/i, severity: 'high', label: 'Prompt injection: safety bypass' },
  { pattern: /system\s*:\s*you\s+are/i,                          severity: 'high', label: 'Prompt injection: fake system prompt' },
  { pattern: /\[SYSTEM\]\s*override/i,                           severity: 'high', label: 'Prompt injection: system override tag' },
  { pattern: /new\s+instructions?\s*:/i,                         severity: 'high', label: 'Prompt injection: new instructions' },
  { pattern: /\{\{.*system.*prompt.*\}\}/i,                      severity: 'high', label: 'Prompt injection: template injection' },
  { pattern: /<!--.*ignore.*-->/i,                               severity: 'high', label: 'Prompt injection: HTML comment directive' },
  { pattern: /translate.*into.*instructions/i,                   severity: 'high', label: 'Prompt injection: translation attack' },
  { pattern: /repeat\s+after\s+me\s*:/i,                         severity: 'high', label: 'Prompt injection: echo attack' },

  // Credential / secret patterns
  { pattern: /AKIA[0-9A-Z]{16}/,                                severity: 'high', label: 'AWS access key detected' },
  { pattern: /ASIA[0-9A-Z]{16}/,                                severity: 'high', label: 'AWS temporary key detected' },
  { pattern: /aws_secret_access_key\s*[=:]\s*\S{30,}/i,         severity: 'high', label: 'AWS secret key in plaintext' },
  { pattern: /ghp_[A-Za-z0-9]{36}/,                             severity: 'high', label: 'GitHub PAT detected' },
  { pattern: /gho_[A-Za-z0-9]{36}/,                             severity: 'high', label: 'GitHub OAuth token detected' },
  { pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,      severity: 'high', label: 'GitHub fine-grained PAT detected' },
  { pattern: /sk-[A-Za-z0-9]{20,}/,                             severity: 'high', label: 'API secret key detected (OpenAI/Stripe)' },
  { pattern: /sk-ant-[A-Za-z0-9-]{90,}/,                        severity: 'high', label: 'Anthropic API key detected' },
  { pattern: /AIza[0-9A-Za-z\\-_]{35}/,                         severity: 'high', label: 'Google API key detected' },
  { pattern: /xox[bpsa]-[A-Za-z0-9-]{10,}/,                     severity: 'high', label: 'Slack token detected' },
  { pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----/i, severity: 'high', label: 'Private key in plaintext' },
  { pattern: /-----BEGIN\s+CERTIFICATE-----/i,                  severity: 'high', label: 'TLS certificate in plaintext' },
  { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high', label: 'JWT token detected' },
  { pattern: /PRIVATE\s+KEY/i,                                  severity: 'high', label: 'Private key reference' },
  { pattern: /password\s*[=:]\s*["'][^"']{4,}/i,                severity: 'high', label: 'Hardcoded password detected' },
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i,               severity: 'high', label: 'MongoDB connection string with credentials' },
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@/i,                 severity: 'high', label: 'PostgreSQL connection string with credentials' },
  { pattern: /mysql:\/\/[^:]+:[^@]+@/i,                         severity: 'high', label: 'MySQL connection string with credentials' },
  { pattern: /redis:\/\/[^:]*:[^@]+@/i,                         severity: 'high', label: 'Redis connection string with credentials' },

  // Supply-chain attacks
  { pattern: /pip\s+install\s+.*--index-url/i,                  severity: 'high', label: 'Supply-chain: custom PyPI index' },
  { pattern: /pip\s+install\s+.*--extra-index-url/i,            severity: 'high', label: 'Supply-chain: extra PyPI index' },
  { pattern: /npm\s+install.*--registry/i,                      severity: 'high', label: 'Supply-chain: custom npm registry' },
  { pattern: /npm\s+config\s+set\s+registry/i,                  severity: 'high', label: 'Supply-chain: npm registry override' },
  { pattern: /gem\s+install.*--source/i,                         severity: 'high', label: 'Supply-chain: custom gem source' },
  { pattern: /pip\s+install\s+--pre\s/i,                         severity: 'high', label: 'Supply-chain: pre-release package install' },

  // Reverse shells & backdoors
  { pattern: /\/dev\/tcp\//i,                                    severity: 'high', label: 'Bash TCP reverse shell' },
  { pattern: /nc\s+-[elp]+.*\d{2,5}/i,                          severity: 'high', label: 'Netcat listener/reverse shell' },
  { pattern: /ncat\s+-[elp]+/i,                                 severity: 'high', label: 'Ncat reverse shell' },
  { pattern: /python.*socket.*connect/i,                         severity: 'high', label: 'Python socket reverse shell' },
  { pattern: /perl.*socket.*INET/i,                              severity: 'high', label: 'Perl socket reverse shell' },
  { pattern: /ruby.*TCPSocket/i,                                 severity: 'high', label: 'Ruby reverse shell' },
  { pattern: /php.*fsockopen/i,                                  severity: 'high', label: 'PHP reverse shell' },
  { pattern: /socat\s+.*EXEC/i,                                 severity: 'high', label: 'Socat exec shell' },
  { pattern: /mknod.*\/tmp\/.*p.*sh/i,                           severity: 'high', label: 'Named pipe shell' },

  // Persistence / privilege escalation
  { pattern: /crontab\s+-[el]/i,                                 severity: 'high', label: 'Crontab modification' },
  { pattern: /\/etc\/cron\./i,                                   severity: 'high', label: 'System cron directory access' },
  { pattern: /systemctl\s+(enable|start|daemon-reload)/i,        severity: 'high', label: 'Systemd service manipulation' },
  { pattern: /launchctl\s+(load|submit)/i,                       severity: 'high', label: 'macOS LaunchAgent manipulation' },
  { pattern: /\/Library\/LaunchAgents\//i,                       severity: 'high', label: 'macOS LaunchAgent directory access' },
  { pattern: /visudo/i,                                          severity: 'high', label: 'Sudoers file modification' },
  { pattern: /usermod\s+.*-aG\s+(sudo|wheel|root)/i,            severity: 'high', label: 'Privilege escalation via group add' },
  { pattern: /chown\s+root/i,                                   severity: 'high', label: 'Ownership change to root' },
  { pattern: /setuid|setgid|chmod\s+[246]?[0-7][0-7][0-7]\s/i,  severity: 'high', label: 'SUID/SGID bit manipulation' },

  // Container escape
  { pattern: /docker\.sock/i,                                    severity: 'high', label: 'Docker socket access' },
  { pattern: /--privileged/i,                                    severity: 'high', label: 'Privileged container execution' },
  { pattern: /mount\s+.*\/host/i,                                severity: 'high', label: 'Host filesystem mount' },
  { pattern: /nsenter\s+/i,                                      severity: 'high', label: 'Namespace enter (container escape)' },
  { pattern: /capsh\s+--print/i,                                 severity: 'high', label: 'Container capabilities check' },

  { pattern: /\.aws\/credentials\b/i,                           severity: 'high', label: 'AWS credentials file read' },
  { pattern: /\.aws\/config\b/i,                                severity: 'high', label: 'AWS config file read' },
  { pattern: /\.kube\/config\b/i,                               severity: 'high', label: 'Kubeconfig access' },
  { pattern: /\bKUBECONFIG\s*=/i,                               severity: 'high', label: 'Kubeconfig access' },
  { pattern: /(^|\/|~)\.netrc\b/i,                              severity: 'high', label: 'Netrc credentials file read' },
  { pattern: /gcloud\/[^\s]*credentials/i,                      severity: 'high', label: 'GCP credentials file read' },
  { pattern: /application_default_credentials\.json/i,          severity: 'high', label: 'GCP application-default credentials read' },
  { pattern: /\.gnupg\/(secring|private-keys-v1\.d|[^\s]*\.gpg)/i, severity: 'high', label: 'GnuPG private keyring access' },
  { pattern: /(Chrome|Brave|Edge|Chromium)[\/\\][^\n]{0,80}(Login Data|Cookies)\b/i, severity: 'high', label: 'Browser credential store access' },
  { pattern: /(User Data|Default)[\/\\](Login Data|Cookies|Network[\/\\]Cookies)\b/i, severity: 'high', label: 'Browser credential store access' },
  { pattern: /(logins\.json|key4\.db|cookies\.sqlite)\b/i,      severity: 'high', label: 'Firefox credential store access' },
  { pattern: /\.npmrc\b[^\n]{0,80}_authToken/i,                 severity: 'high', label: 'npm auth token file read' },
  { pattern: /_authToken[^\n]{0,80}\.npmrc\b/i,                 severity: 'high', label: 'npm auth token file read' },
  { pattern: /\.pypirc\b[^\n]{0,80}(password|token)\s*[=:]/i,   severity: 'high', label: 'PyPI credentials file read' },
  { pattern: /\.docker\/config\.json/i,                         severity: 'high', label: 'Docker registry auth config read' },
  { pattern: /login\.keychain-db\b/i,                           severity: 'high', label: 'macOS keychain database read' },
  { pattern: /(cat|less|more|head|tail|cp|scp|rsync|curl|base64|xxd|strings|open)\b[^\n]{0,60}\.aws\/credentials/i, severity: 'high', label: 'AWS credentials file read' },
  // The `.example` / `.sample` / `.template` / `.dist` / `.tpl` suffixes are
  // committed, secret-free templates — reading them is benign and must not fire
  // (mirrors the enforce-floor exclusion). A redirect target after `>` is a write,
  // not a read, so the pre-path span forbids `>` (keeps copying a template into a
  // real dotenv benign). The exclusion only fires when the template keyword is the
  // FINAL path token — a trailing arg/quote/separator or end-of-segment — so a real
  // secret hiding behind a template prefix (`.env.example.real`, `.env.example.bak`)
  // still matches. Real `.env`, `.env.local`, `.env.production`, etc. still match.
  { pattern: /(cat|less|more|head|tail|cp|source|base64|xxd)\b[^\n>]{0,40}(^|\/|\s)\.env\b(?!\.?(?:example|sample|template|dist|tpl)(?:[\s'";|&)]|$))(\.[a-z]+)?\b/i, severity: 'high', label: 'Dotenv file read' },

  // ═══════════════════════════════════════════════════════════════════════════
  // MEDIUM — exfiltration, sensitive access, recon, suspicious patterns
  // ═══════════════════════════════════════════════════════════════════════════

  // Environment & config access
  { pattern: /process\.env/i,                                    severity: 'medium', label: 'Environment variable access' },
  { pattern: /\.env\b/,                                          severity: 'medium', label: 'Dotenv file access' },
  { pattern: /cat\s+\/etc\/passwd/i,                             severity: 'medium', label: 'Passwd file read' },
  { pattern: /\/etc\/(shadow|hosts|sudoers|resolv\.conf)/i,      severity: 'medium', label: 'Sensitive system file access' },
  { pattern: /\/etc\/ssl\/private/i,                             severity: 'medium', label: 'SSL private key directory' },
  { pattern: /printenv|env\s*$/i,                                severity: 'medium', label: 'Environment dump' },

  // SSH & key access
  { pattern: /ssh-add/i,                                         severity: 'medium', label: 'SSH key manipulation' },
  { pattern: /~\/\.ssh\//i,                                      severity: 'high', label: 'SSH directory access' },
  { pattern: /ssh-keygen/i,                                      severity: 'medium', label: 'SSH key generation' },
  { pattern: /authorized_keys/i,                                 severity: 'medium', label: 'SSH authorized_keys access' },
  { pattern: /id_rsa|id_ed25519|id_ecdsa/i,                     severity: 'high', label: 'SSH private key file access' },

  // Encoding / obfuscation
  { pattern: /atob\s*\(/i,                                       severity: 'medium', label: 'Base64 decode (JS)' },
  { pattern: /base64\s+-d/i,                                     severity: 'medium', label: 'Base64 decode (CLI)' },
  { pattern: /base64\.b64decode/i,                               severity: 'medium', label: 'Base64 decode (Python)' },
  { pattern: /Buffer\.from\(.*,\s*['"]base64['"]/i,              severity: 'medium', label: 'Base64 decode (Node)' },
  { pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,    severity: 'medium', label: 'Hex-encoded payload' },
  { pattern: /String\.fromCharCode/i,                            severity: 'medium', label: 'Character code obfuscation' },

  // Credential stores
  { pattern: /security\s+find-generic-password/i,                severity: 'medium', label: 'macOS Keychain access' },
  { pattern: /security\s+find-internet-password/i,               severity: 'medium', label: 'macOS Keychain internet password' },
  { pattern: /kwallet/i,                                         severity: 'medium', label: 'KDE Wallet access' },
  { pattern: /gnome-keyring/i,                                   severity: 'medium', label: 'GNOME Keyring access' },
  { pattern: /credential[-\s]?manager/i,                         severity: 'medium', label: 'Credential manager access' },

  // Data exfiltration patterns
  { pattern: /curl\s+.*-X\s+POST\s+.*-d/i,                      severity: 'medium', label: 'HTTP POST data exfiltration' },
  { pattern: /curl\s+.*--upload-file/i,                          severity: 'medium', label: 'File upload via curl' },
  { pattern: /scp\s+.*@/i,                                       severity: 'medium', label: 'Secure copy to remote host' },
  { pattern: /rsync\s+.*@/i,                                     severity: 'medium', label: 'Rsync to remote host' },
  { pattern: /nc\s+.*<\s*\//i,                                   severity: 'medium', label: 'Netcat file exfiltration' },
  { pattern: /tar\s+.*\|\s*curl/i,                               severity: 'medium', label: 'Archive-and-exfiltrate' },
  { pattern: /pbcopy|xclip|xsel/i,                               severity: 'medium', label: 'Clipboard access' },
  { pattern: /screencapture|scrot|screenshot/i,                  severity: 'medium', label: 'Screenshot capture' },

  // Network recon & scanning
  { pattern: /nmap\s+/i,                                         severity: 'medium', label: 'Network port scanning' },
  { pattern: /masscan\s+/i,                                      severity: 'medium', label: 'Mass port scanning' },
  { pattern: /dig\s+.*@/i,                                       severity: 'medium', label: 'DNS query to specific server' },
  { pattern: /nslookup\s+/i,                                     severity: 'medium', label: 'DNS lookup' },
  { pattern: /ifconfig|ip\s+addr/i,                              severity: 'medium', label: 'Network interface enumeration' },
  { pattern: /netstat\s+-[tulpn]/i,                              severity: 'medium', label: 'Network connection listing' },
  { pattern: /ss\s+-[tulpn]/i,                                   severity: 'medium', label: 'Socket statistics' },
  { pattern: /arp\s+-a/i,                                        severity: 'medium', label: 'ARP table dump' },

  // Process & system recon
  { pattern: /whoami/i,                                           severity: 'medium', label: 'User identity check' },
  { pattern: /uname\s+-a/i,                                      severity: 'medium', label: 'System info enumeration' },
  { pattern: /cat\s+\/proc\/(version|cpuinfo|meminfo)/i,         severity: 'medium', label: 'System info via proc' },
  { pattern: /lsof\s+-i/i,                                       severity: 'medium', label: 'Open file/port listing' },
  { pattern: /find\s+\/\s+-perm\s+-4000/i,                       severity: 'medium', label: 'SUID binary search' },
  { pattern: /getcap\s+-r/i,                                     severity: 'medium', label: 'Linux capabilities search' },

  // Python execution
  { pattern: /python[23]?\s+-c\s+["']import/i,                   severity: 'medium', label: 'Python one-liner execution' },
  { pattern: /python[23]?\s+-m\s+http\.server/i,                  severity: 'medium', label: 'Python HTTP server' },
  { pattern: /python[23]?\s+-m\s+SimpleHTTPServer/i,              severity: 'medium', label: 'Python HTTP server (legacy)' },

  // Agent-specific suspicious behavior
  { pattern: /spawn\s+.*agent|fork\s+.*agent/i,                  severity: 'medium', label: 'Agent self-spawn attempt' },
  { pattern: /modify.*system\s*prompt/i,                          severity: 'medium', label: 'System prompt modification attempt' },
  { pattern: /override.*safety/i,                                 severity: 'medium', label: 'Safety override attempt' },
  { pattern: /write.*to.*\.bashrc|\.zshrc|\.profile/i,            severity: 'medium', label: 'Shell profile modification' },
  { pattern: /\.bash_history|\.zsh_history/i,                     severity: 'medium', label: 'Shell history access' },
  { pattern: /keylog|keystroke/i,                                 severity: 'medium', label: 'Keylogging attempt' },

  // ═══════════════════════════════════════════════════════════════════════════
  // LOW — suspicious but frequently legitimate, audit trail
  // ═══════════════════════════════════════════════════════════════════════════

  { pattern: /SELECT\s+\*\s+FROM/i,                              severity: 'low', label: 'Full table scan query' },
  { pattern: /chmod\s+[0-7]*7[0-7]*/i,                           severity: 'low', label: 'World-accessible permission' },
  { pattern: /sudo\s+/i,                                         severity: 'low', label: 'Sudo usage' },
  { pattern: /npm\s+install\s+--global/i,                        severity: 'low', label: 'Global npm package install' },
  { pattern: /pip\s+install\s+\S/i,                              severity: 'low', label: 'Python package install' },
  { pattern: /npm\s+install\s+\S/i,                              severity: 'low', label: 'npm package install' },
  { pattern: /gem\s+install\s+\S/i,                              severity: 'low', label: 'Ruby gem install' },
  { pattern: /cargo\s+install\s+\S/i,                            severity: 'low', label: 'Rust crate install' },
  { pattern: /go\s+install\s+\S/i,                               severity: 'low', label: 'Go package install' },
  { pattern: /brew\s+install\s+\S/i,                             severity: 'low', label: 'Homebrew package install' },
  { pattern: /apt(-get)?\s+install/i,                             severity: 'low', label: 'APT package install' },
  { pattern: /yum\s+install/i,                                   severity: 'low', label: 'Yum package install' },
  { pattern: /docker\s+run\s+/i,                                 severity: 'low', label: 'Docker container run' },
  { pattern: /docker\s+pull\s+/i,                                severity: 'low', label: 'Docker image pull' },
  { pattern: /git\s+push\s+.*--force/i,                          severity: 'low', label: 'Git force push' },
  { pattern: /git\s+reset\s+--hard/i,                            severity: 'low', label: 'Git hard reset' },
  { pattern: /kill\s+-9/i,                                       severity: 'low', label: 'Force kill process' },
  { pattern: /pkill\s+/i,                                        severity: 'low', label: 'Process kill by name' },
  { pattern: /wget\s+http/i,                                     severity: 'low', label: 'File download via wget' },
  { pattern: /curl\s+-[oOsSk]*\s+http/i,                         severity: 'low', label: 'File download via curl' },
  { pattern: /openssl\s+/i,                                      severity: 'low', label: 'OpenSSL usage' },
  { pattern: /gpg\s+/i,                                          severity: 'low', label: 'GPG encryption usage' },
  { pattern: /tar\s+(czf|xzf|cf)/i,                              severity: 'low', label: 'Archive creation/extraction' },
  { pattern: /zip\s+/i,                                          severity: 'low', label: 'Zip archive operation' },

];

// Combined rule set: CORE built-ins + EXTRA expansion rules (~639 total).
// This is the array used by server/index.ts and scripts/build-enforcement-rules.ts.
export const SEVERITY_RULES: SeverityRule[] = [
  ...CORE_SEVERITY_RULES,
  ...EXTRA_SEVERITY_RULES,
];

// The detection-path labels that mirror the catastrophic-6 enforcement floor
// (server/enforceEval.ts CATASTROPHIC). These are the highest-consequence
// intents — root deletion, disk wipe, remote-code-into-shell, reverse shells —
// and an operator must NOT be able to disable them, the same way the floor
// blocks them even in monitor mode. The per-rule enable/disable feature treats
// this set as load-bearing: any attempt to disable one of these labels is
// rejected, and the in-memory disabled-set drops them defensively. Kept here,
// beside the rules themselves, so the protected set can never drift from the
// rule definitions it names. (The fork-bomb floor pattern has no single
// detection-rule equivalent and so is not listed.)
export const CATASTROPHIC_DETECTION_LABELS: ReadonlySet<string> = new Set([
  'Recursive root deletion',           // rm -rf /
  'Filesystem format command',         // mkfs.*
  'Raw disk write via dd',             // dd if=… of=/dev/…
  'Remote code execution via curl',    // curl … | sh
  'Remote code execution via wget',    // wget … | sh
  'Bash TCP reverse shell',            // /dev/tcp/
]);
