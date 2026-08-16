// severityRulesExtra.ts
//
// Gated bulk threat-rule expansion for ClaudeSec.
// Rules added here are ReDoS-safe (bounded quantifiers, no catastrophic-
// backtracking patterns) and deduped against the built-in SEVERITY_RULES set
// defined in server.ts.  At runtime, EXTRA_SEVERITY_RULES is spread into the
// tail of SEVERITY_RULES by server.ts so they participate in the same
// first-match-wins detection loop.
//
// Population is managed by scripts/ruleSelfTest.ts-gated generation tooling —
// do NOT import anything from server.ts (it is the app entrypoint, not a
// clean module).

// `critical` is the highest tier, reserved for active secret EXFILTRATION — a
// credential / `.env` being transmitted off the machine (piped/posted/uploaded/
// scp'd to a network sink). A secret merely present in a file stays `high`.
export type ExtraSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ExtraRule {
  pattern: RegExp;
  severity: ExtraSeverity;
  label: string;
}

export const EXTRA_SEVERITY_RULES: ExtraRule[] = [
  // Destructive filesystem & data destruction.
  // The system roots split into two kinds, because a deep path under them means
  // opposite things. `/etc`, `/boot`, `/sys` and the two binary dirs hold config
  // and executables: deleting any subtree of them breaks the machine, so they
  // stay dangerous at every depth. `/var`, `/usr`, `/lib`, `/opt` and `/srv` hold
  // caches and content, and their deep paths are where routine cleanup lives —
  // `rm -rf /var/lib/apt/lists/*` and `rm -rf /var/cache/apk/*` end almost every
  // Debian and Alpine image build, and `rm -rf /usr/share/doc` is the standard
  // slimming line. The old `\b` after the directory name matched at the following
  // slash, so all three fired at high, and high bakes to `action: block` — the
  // rule was refusing the build step. Those roots now fire only when they ARE the
  // target, plus the second-level trees under `/usr` and `/var` that are as fatal
  // as the root itself (`/usr/bin`, `/var/lib`, …) when named whole. An optional
  // quote is allowed on the left, so `rm -rf "/var"` no longer slips past.
  { pattern: /\brm\s+-rf\s+['"]?(?:\/(?:etc|boot|sys|bin|sbin)\b|\/(?:usr|var)(?:\/(?:bin|sbin|lib|lib64|libexec|local|include|log|db|spool))?\/?(?=$|[\s;&|>)'"])|\/(?:lib|opt|srv)\/?(?=$|[\s;&|>)'"]))/im, severity: 'high',   label: 'rm -rf on critical system directory' },
  // The same `\b` bug the rule above was fixed for, in the home roots. `\b`
  // matched at the slash that FOLLOWS the directory name, so every path under a
  // home tree counted as wiping the home tree: fifteen would-be denials in local
  // history, and all fifteen were `rm -rf /Users/<me>/<project>/node_modules`,
  // `…/dist` or a scratch directory — the most routine cleanup a developer
  // performs. The target must now BE `/Users`, `/home` or `/root`, or a single
  // named home inside one (`/Users/dev`, `/home/ci`, `/Users/*`), and must end
  // there: at end of line, a shell separator, a closing quote or a glob.
  { pattern: /\brm\s+-rf\s+['"]?\/(?:home|root|Users)(?:\/[^\/\s;&|>'"]{1,64})?\/?(?=$|[\s;&|>)'"])/im, severity: 'high',   label: 'rm -rf on home/root directory' },
  { pattern: /rm\s+-rf\s+\/tmp\b/i,                                                       severity: 'medium', label: 'rm -rf on /tmp directory' },
  { pattern: /rm\s+-rf\s+\/dev\b/i,                                                       severity: 'high',   label: 'rm -rf on /dev directory' },
  { pattern: /rm\s+-rf\s+\/proc\b/i,                                                      severity: 'high',   label: 'rm -rf on /proc pseudo-filesystem' },
  { pattern: /rm\s+-rf\s+\/mnt\b/i,                                                       severity: 'high',   label: 'rm -rf on mounted volume path' },
  { pattern: /rm\s+-rf\s+\/media\b/i,                                                     severity: 'high',   label: 'rm -rf on /media directory' },
  { pattern: /rm\s+--no-preserve-root/i,                                                  severity: 'high',   label: 'rm with --no-preserve-root flag' },
  { pattern: />\s*\/dev\/sd[a-z]\b/i,                                                     severity: 'high',   label: 'Redirect output to raw block device' },
  { pattern: /dd\s+if=\/dev\/zero\s+of=\/dev\/sd[a-z]/i,                                 severity: 'high',   label: 'dd zero-wipe raw disk' },
  { pattern: /dd\s+if=\/dev\/urandom\s+of=\/dev\/sd[a-z]/i,                              severity: 'high',   label: 'dd random-wipe raw disk' },
  { pattern: /mkfs\.[a-z0-9]{2,10}\s+\/dev\/sd[a-z]/i,                                  severity: 'high',   label: 'mkfs format on block device' },
  { pattern: /wipefs\s+/i,                                                                severity: 'high',   label: 'wipefs partition signature erasure' },
  { pattern: /blkdiscard\s+\/dev\//i,                                                     severity: 'high',   label: 'blkdiscard SSD wipe' },
  { pattern: /shred\s+-[uzn]*\s+\/(?:etc|var|home|root|boot)/i,                          severity: 'high',   label: 'shred on system/home path' },
  { pattern: /wipe\s+\/dev\/sd[a-z]/i,                                                    severity: 'high',   label: 'wipe utility on block device' },
  { pattern: /:\(\)\{.*:\|:&\};:/,                                                        severity: 'high',   label: 'Fork bomb' },
  { pattern: /find\s+\/(?:etc|var|home|root|usr)\s+.*-delete\b/i,                        severity: 'high',   label: 'find -delete on system path' },
  { pattern: /find\s+\/\s+.*-delete\b/i,                                                  severity: 'high',   label: 'find -delete from filesystem root' },
  { pattern: /truncate\s+-s\s+0\s+\/(?:etc|var|home|root)\//i,                           severity: 'high',   label: 'truncate to zero bytes on system file' },
  { pattern: /chattr\s+\+i\s+\/(?:etc|var|usr|boot)/i,                                   severity: 'high',   label: 'chattr immutable on system directory' },
  { pattern: /chflags\s+.*schg\s+/i,                                                      severity: 'high',   label: 'chflags system immutable on file' },
  { pattern: /rm\s+-rf\s+.*\.git\b/i,                                                     severity: 'high',   label: 'rm -rf on .git directory' },
  { pattern: /rm\s+-rf\s+.*backup/i,                                                      severity: 'medium', label: 'rm -rf on backup directory' },
  { pattern: /rm\s+-rf\s+.*\/log[s]?\b/i,                                                 severity: 'medium', label: 'rm -rf on log directory' },
  { pattern: />\s*\/var\/log\/[a-z]/i,                                                    severity: 'medium', label: 'Overwrite system log file' },
  { pattern: /cat\s+\/dev\/null\s+>\s+\/var\/log\//i,                                     severity: 'medium', label: 'Null-out system log via cat redirect' },
  { pattern: /history\s+-c\b/i,                                                           severity: 'medium', label: 'Shell history clear command' },
  { pattern: /rm\s+-f\s+.*\.bash_history/i,                                               severity: 'medium', label: 'Delete bash history file' },
  { pattern: /unlink\s+\/(?:etc|var|usr|bin|home)\//i,                                    severity: 'high',   label: 'unlink on system path file' },
  { pattern: /fallocate\s+.*--length\s+0\s+\/(?:etc|var|home)\//i,                        severity: 'high',   label: 'fallocate truncate on system file' },
  { pattern: /secure-delete\s+\/(?:etc|var|home|root)\//i,                                severity: 'high',   label: 'secure-delete on system path' },
  // Database destruction & dump
  // These four, and the Cassandra keyspace rule further down, are the same
  // unanchored keyword matchers that detection.ts demoted to the alert tier —
  // see the note beside `SQL destructive operation` there. They have to move
  // together: matching is first-wins over core-then-extra, so leaving a
  // duplicate here at `high` would simply re-block everything the core demotion
  // was meant to stop refusing. The act still blocks, through
  // `SQL destructive statement executed through a database client` and the
  // `psql`/`mysql` inline rules below.
  { pattern: /DROP\s+DATABASE\s+\w/i,                                                     severity: 'medium', label: 'SQL DROP DATABASE statement' },
  { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?\w/i,                                    severity: 'medium', label: 'SQL DROP TABLE (with optional IF EXISTS)' },
  { pattern: /DROP\s+SCHEMA\s+(?:IF\s+EXISTS\s+)?\w/i,                                   severity: 'medium', label: 'SQL DROP SCHEMA statement' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i,                                 severity: 'high',   label: 'SQL DELETE with always-true WHERE (full wipe)' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+['"1]1['"1]?\s*=\s*['"1]1/i,                severity: 'high',   label: 'SQL injection-style DELETE all rows' },
  { pattern: /UPDATE\s+\w+\s+SET\s+\w+\s*=\s*.*WHERE\s+1\s*=\s*1/i,                     severity: 'high',   label: 'SQL UPDATE with always-true WHERE (full wipe)' },
  { pattern: /TRUNCATE\s+(?:TABLE\s+)?\w+\s+(?:CASCADE|RESTART)/i,                       severity: 'high',   label: 'SQL TRUNCATE with CASCADE or RESTART' },
  { pattern: /DROP\s+TABLE\s+.*CASCADE/i,                                                  severity: 'medium', label: 'SQL DROP TABLE CASCADE' },
  { pattern: /ALTER\s+TABLE\s+\w+\s+DROP\s+CONSTRAINT/i,                                  severity: 'medium', label: 'SQL DROP CONSTRAINT on table' },
  { pattern: /mysqldump\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                               severity: 'high',   label: 'mysqldump piped to network transfer' },
  { pattern: /pg_dump\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                                 severity: 'high',   label: 'pg_dump piped to network transfer' },
  { pattern: /sqlite3\s+.*\.dump\s*\|\s*(?:curl|wget|nc)/i,                               severity: 'high',   label: 'SQLite dump piped to network' },
  { pattern: /mysqldump\s+.*-h\s+\S/i,                                                    severity: 'medium', label: 'mysqldump to remote host' },
  // `-h localhost` is how nearly every local backup script is written, so the
  // host argument is the whole signal: only a NON-loopback target means the dump
  // is leaving this machine.
  { pattern: /pg_dump\s+[^\n]{0,120}-h\s+(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|::1\b)\S/i, severity: 'medium', label: 'pg_dump to remote host' },
  { pattern: /mysql\s+.*-e\s+["']DROP\s+DATABASE/i,                                       severity: 'high',   label: 'mysql CLI inline DROP DATABASE' },
  { pattern: /psql\s+.*-c\s+["']DROP\s+DATABASE/i,                                        severity: 'high',   label: 'psql CLI inline DROP DATABASE' },
  { pattern: /psql\s+.*-c\s+["']TRUNCATE/i,                                               severity: 'high',   label: 'psql CLI inline TRUNCATE' },
  { pattern: /mongo\s+.*dropDatabase\s*\(/i,                                               severity: 'high',   label: 'MongoDB dropDatabase() call' },
  { pattern: /db\.dropDatabase\s*\(/i,                                                     severity: 'high',   label: 'MongoDB db.dropDatabase() in shell/code' },
  { pattern: /db\.getCollection\s*\(.*\)\.drop\s*\(/i,                                    severity: 'high',   label: 'MongoDB collection.drop() call' },
  { pattern: /\.collection\s*\(.*\)\.drop\s*\(/i,                                         severity: 'high',   label: 'MongoDB collection drop via driver' },
  { pattern: /redis-cli\s+FLUSHALL\b/i,                                                   severity: 'high',   label: 'Redis FLUSHALL via CLI' },
  { pattern: /redis-cli\s+FLUSHDB\b/i,                                                    severity: 'high',   label: 'Redis FLUSHDB via CLI' },
  { pattern: /\.flushAll\s*\(/i,                                                           severity: 'high',   label: 'Redis FLUSHALL via client library' },
  { pattern: /\.flushDb\s*\(/i,                                                            severity: 'high',   label: 'Redis FLUSHDB via client library' },
  { pattern: /dynamo.*deleteTable\s*\(/i,                                                  severity: 'high',   label: 'DynamoDB deleteTable() call' },
  { pattern: /elasticsearch.*deleteIndex\s*\(/i,                                           severity: 'medium', label: 'Elasticsearch deleteIndex() call' },
  { pattern: /DROP\s+KEYSPACE\s+\w/i,                                                     severity: 'medium', label: 'Cassandra DROP KEYSPACE' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+id\s+(?:IN|NOT\s+IN)\s*\(\s*SELECT/i,        severity: 'medium', label: 'SQL mass DELETE via subquery' },
  { pattern: /influx\s+.*delete\s+.*--bucket/i,                                           severity: 'high',   label: 'InfluxDB bucket delete via CLI' },
  { pattern: /pg_dumpall\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                              severity: 'high',   label: 'pg_dumpall piped to network transfer' },
  { pattern: /CALL\s+mysql\.rds_kill_query/i,                                              severity: 'medium', label: 'RDS kill query stored procedure' },
  // category: Remote code execution / download-and-run
  { pattern: /curl\s+[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'curl pipe to shell' },
  { pattern: /curl\s+[^|;&\n]*\|\s*bash\b/i, severity: 'high', label: 'curl pipe to bash' },
  { pattern: /wget\s+[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'wget pipe to shell' },
  { pattern: /wget\s+[^|;&\n]*\|\s*bash\b/i, severity: 'high', label: 'wget pipe to bash' },
  // The same stdin-is-the-program test detection.ts applies to `curl … | python`
  // — see the long note there — and mandatory here for the same first-wins
  // reason as the SQL block above: these are broader duplicates of the core
  // rules, so tightening only the core would have handed every released match
  // straight back to these. Node gets the equivalent treatment: `-e` / `-p`
  // supply the program, and `curl … | node -e '…JSON.parse(d)…'` was ten of the
  // ten `curl pipe to node` matches in local history. An inline program that can
  // still execute what it reads (`eval`, `Function(`, `child_process`, `vm`)
  // keeps firing.
  { pattern: /curl\s+[^|;&\n]*\|\s*python\d*(?:\.\d+)?\b(?![^\n|;&]{0,120}\s-{1,2}m\s*(?:json(?:\.tool)?|base64|csv|gzip|bz2|lzma|zipfile|tarfile|hashlib|pprint|tomllib|calendar)\b)(?![^\n|;&]{0,120}\s-{1,2}c\b(?![^\n]{0,240}(?:\bexec\b|\beval\b|\bcompile\b|__import__|os\.system|os\.popen|subprocess|runpy|importlib|pickle|marshal|pty\.spawn)))/i, severity: 'high', label: 'curl pipe to python' },
  { pattern: /wget\s+[^|;&\n]*\|\s*python\d*(?:\.\d+)?\b(?![^\n|;&]{0,120}\s-{1,2}m\s*(?:json(?:\.tool)?|base64|csv|gzip|bz2|lzma|zipfile|tarfile|hashlib|pprint|tomllib|calendar)\b)(?![^\n|;&]{0,120}\s-{1,2}c\b(?![^\n]{0,240}(?:\bexec\b|\beval\b|\bcompile\b|__import__|os\.system|os\.popen|subprocess|runpy|importlib|pickle|marshal|pty\.spawn)))/i, severity: 'high', label: 'wget pipe to python' },
  { pattern: /curl\s+[^|;&\n]*\|\s*perl\b/i, severity: 'high', label: 'curl pipe to perl' },
  { pattern: /curl\s+[^|;&\n]*\|\s*ruby\b/i, severity: 'high', label: 'curl pipe to ruby' },
  { pattern: /curl\s+[^|;&\n]*\|\s*node\b(?![^\n|;&]{0,120}\s-{1,2}(?:e|p|eval|print)\b(?![^\n]{0,240}(?:\beval\b|\bFunction\s*\(|child_process|\bvm\.|execSync|spawnSync)))/i, severity: 'high', label: 'curl pipe to node' },
  { pattern: /wget\s+[^|;&\n]*\|\s*perl\b/i, severity: 'high', label: 'wget pipe to perl' },
  { pattern: /wget\s+[^|;&\n]*\|\s*node\b(?![^\n|;&]{0,120}\s-{1,2}(?:e|p|eval|print)\b(?![^\n]{0,240}(?:\beval\b|\bFunction\s*\(|child_process|\bvm\.|execSync|spawnSync)))/i, severity: 'high', label: 'wget pipe to node' },
  { pattern: /curl\s+-[A-Za-z]*[oO][A-Za-z]*\s+\S+\s+http[s]?:\/\//i, severity: 'high', label: 'curl download to file from URL' },
  // `-O -` writes to stdout, the documented way to pipe a key/installer into a
  // reader; only a real output FILE means an artifact is being staged on disk.
  { pattern: /wget\s+-[A-Za-z]*O\s+(?!-\s)\S+\s+http[s]?:\/\//i, severity: 'high', label: 'wget download to file from URL' },
  { pattern: /git\s+clone\s+http[s]?:\/\/[^&;\n]+&&\s*(?:\.\/|bash\s|sh\s)/i, severity: 'high', label: 'git clone then execute' },
  { pattern: /git\s+clone\s+http[s]?:\/\/[^&;\n]+;\s*(?:\.\/|bash\s|sh\s)/i, severity: 'high', label: 'git clone semicolon execute' },
  { pattern: /Invoke-WebRequest\s+[^|;&\n]*\|\s*Invoke-Expression/i, severity: 'high', label: 'PowerShell IWR pipe to IEX' },
  { pattern: /iwr\s+[^|;&\n]*\|\s*iex\b/i, severity: 'high', label: 'PowerShell iwr pipe to iex' },
  { pattern: /Invoke-Expression\s*\(\s*\(\s*(?:New-Object|iwr)\b/i, severity: 'high', label: 'PowerShell IEX wrapping download' },
  { pattern: /certutil\s+-urlcache\s+-[A-Za-z]*f[A-Za-z]*\s+http[s]?:\/\//i, severity: 'high', label: 'certutil urlcache download' },
  { pattern: /bitsadmin\s+\/transfer\s+\S+\s+http[s]?:\/\//i, severity: 'high', label: 'bitsadmin file transfer from URL' },
  { pattern: /powershell[^|;&\n]*-(?:command|c)\s+['"]\s*(?:iex|Invoke-Expression)\s*\(/i, severity: 'high', label: 'PowerShell command IEX download exec' },
  { pattern: /\$\s*\(\s*(?:New-Object\s+System\.Net\.WebClient|iwr)\b[^)]*\)\.Download(?:String|File)\s*\(/i, severity: 'high', label: 'PowerShell WebClient download' },
  { pattern: /curl\s+[^|;&\n]*\|\s*sudo\s+(?:ba)?sh/i, severity: 'high', label: 'curl pipe to sudo shell' },
  { pattern: /wget\s+[^|;&\n]*\|\s*sudo\s+(?:ba)?sh/i, severity: 'high', label: 'wget pipe to sudo shell' },
  { pattern: /fetch\s*\(\s*['"][^'"]*['"]\s*\)[^;]*\.then[^;]*(?:eval|Function\s*\()/i, severity: 'high', label: 'fetch then eval remote script' },
  { pattern: /python3?\s+-c\s+['"](?:import\s+urllib|import\s+requests)[^'"]*exec\s*\(/i, severity: 'high', label: 'python one-liner download and exec' },
  { pattern: /(?:curl|wget)\s+[^|;&\n]*\|\s*(?:ba)?sh\s+-s\b/i, severity: 'high', label: 'download pipe to shell with -s flag' },
  { pattern: /Start-BitsTransfer\s+[^|;&\n]*http[s]?:\/\//i, severity: 'medium', label: 'PowerShell Start-BitsTransfer from URL' },
  { pattern: /(?:curl|wget)\s+[^|;&\n]*\s+-q\s+[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'quiet download pipe to shell' },
  { pattern: /mshta\s+(?:vbscript:|http[s]?:\/\/)\S+/i, severity: 'high', label: 'mshta remote script execution' },
  { pattern: /regsvr32\s+\/s\s+\/[un]\s+\/i:http[s]?:\/\//i, severity: 'high', label: 'regsvr32 COM scriptlet from URL' },
  { pattern: /rundll32\s+[^|;&\n]*javascript:/i, severity: 'high', label: 'rundll32 javascript protocol exec' },
  // category: Encoded / obfuscated payload execution
  { pattern: /base64\s+-d\s*\|\s*(?:ba)?sh/i, severity: 'high', label: 'base64 decode pipe to shell' },
  { pattern: /base64\s+--decode\s*\|\s*(?:ba)?sh/i, severity: 'high', label: 'base64 --decode pipe to shell' },
  { pattern: /base64\s+-d\s*\|\s*python3?/i, severity: 'high', label: 'base64 decode pipe to python' },
  { pattern: /base64\s+-d\s*\|\s*perl\b/i, severity: 'high', label: 'base64 decode pipe to perl' },
  { pattern: /eval\s*\(\s*atob\s*\(/i, severity: 'high', label: 'eval(atob(...)) encoded payload' },
  { pattern: /Function\s*\(\s*atob\s*\(\s*['"][A-Za-z0-9+\/=]{16,}['"]\s*\)\s*\)/i, severity: 'high', label: 'Function constructor with atob payload' },
  { pattern: /new\s+Function\s*\(\s*(?:Buffer|atob)\s*\(/i, severity: 'high', label: 'new Function from decoded buffer' },
  { pattern: /powershell(?:\.exe)?\s+-enc(?:odedcommand)?\s+[A-Za-z0-9+\/=]{16,}/i, severity: 'high', label: 'PowerShell encoded command' },
  { pattern: /powershell(?:\.exe)?\s+-e\s+[A-Za-z0-9+\/=]{16,}/i, severity: 'high', label: 'PowerShell -e encoded payload' },
  { pattern: /echo\s+[0-9a-fA-F]{20,}\s*\|\s*xxd\s+-r/i, severity: 'high', label: 'echo hex blob pipe to xxd decode' },
  { pattern: /xxd\s+-r[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'xxd decode pipe to shell' },
  { pattern: /python3?\s+-c\s+['"]exec\s*\(\s*(?:__import__\s*\(\s*'base64'\s*\)|base64)\b/i, severity: 'high', label: 'python exec(base64...) one-liner' },
  { pattern: /python3?\s+-c\s+['"]import\s+base64[^'"]*exec\s*\(/i, severity: 'high', label: 'python import base64 then exec' },
  { pattern: /python3?\s+-c\s+['"]exec\s*\(\s*compile\s*\(\s*(?:base64|zlib)\b/i, severity: 'high', label: 'python exec(compile(base64...))' },
  { pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}[^'"]*exec\s*\(/i, severity: 'high', label: 'hex escape sequence feeding exec' },
  { pattern: /eval\s*\(\s*['"]\\x[0-9a-fA-F]{2}/i, severity: 'high', label: 'eval with leading hex escape payload' },
  { pattern: /String\.fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){8,}\s*\)[^;]*eval\s*\(/i, severity: 'high', label: 'char-code array eval obfuscation' },
  { pattern: /(?:zlib|gzip)\s*\.\s*decompress[^|;&\n]*exec\s*\(/i, severity: 'high', label: 'zlib/gzip decompress then exec' },
  { pattern: /echo\s+[A-Za-z0-9+\/=]{32,}\s*\|\s*base64\s+-d\s*\|\s*(?:ba)?sh/i, severity: 'high', label: 'echo base64 blob decode pipe to shell' },
  { pattern: /ruby\s+-e\s+['"]require\s+'base64'[^'"]*eval\s*\(/i, severity: 'high', label: 'ruby eval base64 one-liner' },
  { pattern: /perl\s+-e\s+['"][^'"]*eval\s*\(\s*(?:unpack|decode_base64)\b/i, severity: 'high', label: 'perl eval with decode one-liner' },
  { pattern: /node\s+-e\s+['"][^'"]*Buffer\.from\s*\(\s*['"][A-Za-z0-9+\/=]{16,}['"]\s*,\s*'base64'\s*\)[^'"]*eval\s*\(/i, severity: 'high', label: 'node eval Buffer.from base64 payload' },
  { pattern: /document\s*\[\s*['"]write['"]\s*\]\s*\(\s*(?:eval|unescape)\s*\(/i, severity: 'medium', label: 'document.write eval obfuscated output' },
  { pattern: /unescape\s*\(\s*['"]%[0-9a-fA-F]{2}/i, severity: 'medium', label: 'unescape percent-encoded payload' },
  { pattern: /(?:eval|setTimeout|setInterval)\s*\(\s*unescape\s*\(\s*['"]%[0-9a-fA-F]/i, severity: 'high', label: 'eval/timer with unescape payload' },
  { pattern: /exec\s*\(\s*base64\.b64decode\s*\(/i, severity: 'high', label: 'python exec(base64.b64decode(...))' },
  { pattern: /os\.system\s*\(\s*base64\.b64decode\s*\(/i, severity: 'high', label: 'os.system with base64 decoded payload' },
  { pattern: /subprocess\s*\.\s*(?:call|run|Popen)\s*\([^)]*base64\s*\.\s*b64decode\s*\(/i, severity: 'high', label: 'subprocess call with base64 decode' },
  { pattern: /eval\s*\(\s*Buffer\s*\.\s*from\s*\(\s*['"][A-Za-z0-9+\/=]{16,}['"]/i, severity: 'high', label: 'eval Buffer.from base64 in node' },
  { pattern: /(?:exec|eval)\s*\(\s*(?:LZString|pako|zlib)\s*\.\s*decompress/i, severity: 'high', label: 'exec/eval compressed payload decompression' },
  { pattern: /powershell[^|;&\n]*-[Ww]indow[Ss]tyle\s+[Hh]idden[^|;&\n]*-[Ee]nc/i, severity: 'high', label: 'PowerShell hidden window with encoded command' },
  { pattern: /(?:base64|b64)\s*\.\s*(?:b64decode|decodebytes)\s*\([^)]*\)[^;]*(?:exec|eval|compile)\s*\(/i, severity: 'high', label: 'base64 decode then exec/eval/compile' },
  // category: Reverse Shells & C2
  { pattern: /bash\s+-i\s+>&\s*\/dev\/tcp\//i, severity: 'high', label: 'bash reverse shell via /dev/tcp' },
  { pattern: /0>&1\s*&?\s*$/, severity: 'high', label: 'bash stdin/stdout redirect for reverse shell' },
  { pattern: /\/dev\/tcp\/[0-9a-z.\-]+\/[0-9]+/i, severity: 'high', label: '/dev/tcp reverse shell redirect' },
  { pattern: /\/dev\/udp\/[0-9a-z.\-]+\/[0-9]+/i, severity: 'high', label: '/dev/udp reverse shell redirect' },
  { pattern: /nc\s+.*-e\s+(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i, severity: 'high', label: 'netcat reverse shell with -e exec' },
  { pattern: /ncat\s+.*-e\s+(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i, severity: 'high', label: 'ncat reverse shell with -e exec' },
  { pattern: /nc\s+.*-c\s+(?:sh|bash|cmd|powershell)/i, severity: 'high', label: 'netcat reverse shell with -c shell' },
  { pattern: /mkfifo\s+\S+\s*;.*nc\s+/i, severity: 'high', label: 'mkfifo backpipe netcat reverse shell' },
  { pattern: /rm\s+-f\s+\S+\s*;.*mkfifo\s+\S+\s*;.*nc\s+/i, severity: 'high', label: 'mkfifo cleanup+backpipe reverse shell' },
  { pattern: /socat\s+.*EXEC:(?:\/bin\/sh|\/bin\/bash|cmd\.exe)/i, severity: 'high', label: 'socat exec reverse shell' },
  { pattern: /socat\s+.*TCP[46]?:[^,]+,\s*SYSTEM:/i, severity: 'high', label: 'socat SYSTEM reverse shell' },
  { pattern: /python[23]?\s+-c\s+["'].*socket.*connect.*sh["']/i, severity: 'high', label: 'python reverse shell one-liner' },
  { pattern: /python[23]?\s+-c\s+["'].*subprocess.*socket.*STDOUT/i, severity: 'high', label: 'python subprocess socket reverse shell' },
  { pattern: /perl\s+-e\s+["'].*socket.*STDIN.*STDOUT.*STDERR["']/i, severity: 'high', label: 'perl reverse shell one-liner' },
  { pattern: /ruby\s+-rsocket\s+-e\s+["'].*TCPSocket/i, severity: 'high', label: 'ruby TCPSocket reverse shell' },
  { pattern: /php\s+-r\s+["'].*fsockopen.*sh["']/i, severity: 'high', label: 'php fsockopen reverse shell' },
  { pattern: /php\s+-r\s+["'].*exec\(["']\/bin\/(?:sh|bash)["']/i, severity: 'high', label: 'php exec shell spawn' },
  { pattern: /powershell.*TCPClient.*GetStream.*StreamWriter/i, severity: 'high', label: 'PowerShell TCPClient reverse shell' },
  { pattern: /\$client\s*=\s*New-Object\s+Net\.Sockets\.TCPClient/i, severity: 'high', label: 'PowerShell New-Object TCPClient' },
  { pattern: /IEX\s*\(\s*New-Object\s+Net\.WebClient\s*\)\.DownloadString/i, severity: 'high', label: 'PowerShell IEX remote download-execute' },
  { pattern: /msfvenom\s+-p\s+\S*(reverse_tcp|reverse_shell|meterpreter)/i, severity: 'high', label: 'msfvenom reverse payload generation' },
  { pattern: /msfconsole\s+-x\s+["']use\s+exploit/i, severity: 'high', label: 'msfconsole automated exploit launch' },
  { pattern: /msf[45]?\/handler.*reverse/i, severity: 'high', label: 'Metasploit multi/handler reverse shell' },
  { pattern: /\bcobalt[_\s]?strike\b/i, severity: 'high', label: 'Cobalt Strike C2 reference' },
  { pattern: /beacon\.dll|cobaltstrike.*beacon/i, severity: 'high', label: 'Cobalt Strike beacon artifact' },
  { pattern: /sliver[-_\s]?server|sliver[-_\s]?client\b/i, severity: 'high', label: 'Sliver C2 framework' },
  { pattern: /c2\s+beacon.*http[s]?:\/\//i, severity: 'high', label: 'C2 beacon URL in span' },
  { pattern: /havoc\s+teamserver|havoc_client/i, severity: 'high', label: 'Havoc C2 framework reference' },
  { pattern: /pty\.spawn\s*\(["']\/bin\/(?:bash|sh)["']\)/i, severity: 'high', label: 'Python pty shell spawn (upgrade shell)' },
  { pattern: /script\s+-qc?\s+\/bin\/(?:bash|sh)\s+\/dev\/null/i, severity: 'high', label: 'script -qc /bin/sh /dev/null shell upgrade' },
  { pattern: /stty\s+raw\s+-echo\s*;\s*fg/i, severity: 'high', label: 'TTY raw mode shell stabilization' },
  { pattern: /LHOST=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*LPORT=\d+/i, severity: 'high', label: 'Metasploit LHOST/LPORT payload parameters' },
  // category: Crypto-Mining & Resource Abuse
  { pattern: /\bxmrig\b/i, severity: 'medium', label: 'XMRig miner binary' },
  { pattern: /\bminerd\b/i, severity: 'medium', label: 'minerd CPU miner binary' },
  { pattern: /\bcpuminer\b/i, severity: 'medium', label: 'cpuminer binary' },
  { pattern: /stratum\+tcp:\/\//i, severity: 'medium', label: 'stratum+tcp mining pool connection' },
  { pattern: /stratum\+ssl:\/\//i, severity: 'medium', label: 'stratum+ssl encrypted mining pool' },
  { pattern: /stratum2\+tcp:\/\//i, severity: 'medium', label: 'stratum2 mining pool protocol' },
  { pattern: /pool\.minexmr\.com/i, severity: 'medium', label: 'MineXMR pool domain' },
  { pattern: /supportxmr\.com/i, severity: 'medium', label: 'SupportXMR pool domain' },
  { pattern: /nanopool\.org/i, severity: 'medium', label: 'Nanopool mining pool domain' },
  { pattern: /hashvault\.pro/i, severity: 'medium', label: 'HashVault mining pool domain' },
  { pattern: /moneroocean\.stream/i, severity: 'medium', label: 'MoneroOcean pool domain' },
  { pattern: /2miners\.com/i, severity: 'medium', label: '2Miners pool domain' },
  { pattern: /nicehash\.com/i, severity: 'medium', label: 'NiceHash pool or marketplace' },
  { pattern: /coinhive\.com/i, severity: 'medium', label: 'Coinhive browser miner domain' },
  { pattern: /cryptonight/i, severity: 'medium', label: 'CryptoNight mining algorithm reference' },
  { pattern: /randomx\s+--threads/i, severity: 'medium', label: 'RandomX miner with thread flag' },
  { pattern: /--donate-level\s+[0-9]/i, severity: 'medium', label: 'XMRig --donate-level flag (miner config)' },
  { pattern: /--coin\s+(?:xmr|monero|eth|rvn|ergo)/i, severity: 'medium', label: 'miner --coin cryptocurrency flag' },
  { pattern: /-o\s+stratum[+\w]*:\/\/\S+\s+-u\s+\S+wallet/i, severity: 'medium', label: 'miner pool URL with wallet user flag' },
  { pattern: /--threads\s+[0-9]+\s+--url\s+stratum/i, severity: 'medium', label: 'miner threads+URL combo flags' },
  { pattern: /mining.*wallet.*address.*[0-9a-f]{95,}/i, severity: 'medium', label: 'Monero-length wallet address in mining context' },
  { pattern: /4[0-9AB][0-9a-zA-Z]{93}/, severity: 'low', label: 'Possible Monero wallet address (95-char)' },
  { pattern: /wget\s+-q.*xmrig.*\.tar|curl\s+-s.*xmrig.*\.tar/i, severity: 'high', label: 'Downloading XMRig tarball via wget/curl' },
  { pattern: /curl\s+-s\s+https?:\/\/\S+\s*\|\s*(?:bash|sh)/i, severity: 'high', label: 'curl-pipe-bash remote script execution' },
  { pattern: /wget\s+-O\s*-\s+https?:\/\/\S+\s*\|\s*(?:bash|sh)/i, severity: 'high', label: 'wget-pipe-bash remote script execution' },
  { pattern: /crontab.*@reboot.*xmrig/i, severity: 'high', label: 'XMRig persistence via crontab @reboot' },
  { pattern: /systemctl\s+enable.*(?:xmrig|miner|kworker[0-9])/i, severity: 'high', label: 'miner systemd service persistence' },
  { pattern: /ulimit\s+-[snHu]\s+unlimited/i, severity: 'low', label: 'ulimit set to unlimited (resource abuse setup)' },
  { pattern: /hugePages.*miner|miner.*hugepages/i, severity: 'low', label: 'HugePages config for miner optimization' },
  { pattern: /--max-cpu-usage\s+[89][0-9]|--max-cpu-usage\s+100/i, severity: 'medium', label: 'Miner max CPU usage set to 90-100%' },
  { pattern: /nicehash.*lhr|nhqm.*stratum/i, severity: 'medium', label: 'NiceHash LHR bypass or protocol config' },
  { pattern: /kworker[0-9\/]+:\s*\[.*miner/i, severity: 'medium', label: 'Miner disguised as kworker kernel thread' },
  { pattern: /chmod\s+\+x.*xmrig|chmod\s+777.*miner/i, severity: 'medium', label: 'Making miner binary executable' },
  // ─────────────────────────────────────────────────────────────────────────────
  // Category: Credential & secret theft
  // ─────────────────────────────────────────────────────────────────────────────
  // SSH private key file reads (specific key names not already caught)
  // The `.pub` half of a keypair is public by design — printing it is the normal
  // way to hand a key to a server, so only the private half counts as a read.
  { pattern: /\bcat\b[^\n]{0,60}\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)\b/i, severity: 'high', label: 'SSH private key read via cat' },
  { pattern: /\bcp\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key copy' },
  { pattern: /\bscp\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'critical', label: 'SSH private key remote copy' },
  { pattern: /\bbase64\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key base64 encoding' },
  { pattern: /\bstrings\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key strings extraction' },
  // /etc/shadow read (the existing rule matches access, add targeted read forms)
  { pattern: /\b(cat|less|more|head|tail|strings|xxd|base64)\b[^\n]{0,40}\/etc\/shadow\b/i, severity: 'high', label: '/etc/shadow direct read' },
  { pattern: /\bunshadow\b/i, severity: 'high', label: 'Unshadow password file (passwd+shadow merge)' },
  { pattern: /john\s+.*--format[^\n]{0,60}shadow/i, severity: 'high', label: 'John-the-Ripper shadow hash crack' },
  // .env exfiltration (read + send patterns not caught by existing dotenv rule)
  { pattern: /\benv\b[^\n]{0,40}\|\s*(curl|wget|nc|ncat|python|ruby)\b/i, severity: 'critical', label: '.env / env vars piped to exfil tool' },
  { pattern: /printenv[^\n]{0,60}\|\s*(curl|wget|nc|ncat)\b/i, severity: 'critical', label: 'printenv output piped to exfil' },
  { pattern: /\benv\s+\|\s*grep\s+-[iEP]{1,3}\s+['"]?(secret|token|key|pass|pwd|api)/i, severity: 'high', label: 'Env secret grep (targeted sweep)' },
  // git credential theft
  { pattern: /git\s+config\s+--(?:global|local|system)\s+.*credential/i, severity: 'high', label: 'git credential config read/write' },
  { pattern: /git\s+credential\s+(fill|get|approve|reject)/i, severity: 'high', label: 'git credential store query' },
  { pattern: /git\s+config\s+--get\s+.*(?:password|token|secret)/i, severity: 'high', label: 'git config credential key read' },
  // macOS keychain dump
  { pattern: /security\s+dump-keychain/i, severity: 'high', label: 'macOS keychain full dump' },
  { pattern: /security\s+export\s+-t\s+(certs|keys|identities)/i, severity: 'high', label: 'macOS keychain export keys/certs' },
  { pattern: /security\s+find-certificate\s+-a/i, severity: 'medium', label: 'macOS keychain all-certs enumeration' },
  // Shell history scraping for secrets
  { pattern: /grep\s+-[iEhrl]{0,4}\s*['"]?(secret|token|password|api.?key|passwd)\b[^\n]{0,60}(\.bash_history|\.zsh_history|\.sh_history)/i, severity: 'high', label: 'Shell history grep for secrets' },
  { pattern: /\bhistory\b[^\n]{0,40}\|\s*grep\s+-[iE]{0,2}\s*['"]?(secret|token|password|api.?key)/i, severity: 'high', label: 'history command piped to secret grep' },
  // ~/.config/gcloud credential files
  { pattern: /\.config\/gcloud\/[^\s]{0,60}(access_token|credentials|adc)\b/i, severity: 'high', label: 'GCP gcloud ADC/access-token file read' },
  { pattern: /\b(cat|cp|base64|curl)\b[^\n]{0,60}\.config\/gcloud\b/i, severity: 'high', label: 'GCP gcloud config directory read/copy' },
  // netrc (not fully covered — existing rule matches .netrc path; add exfil form)
  { pattern: /\b(cat|base64|strings|curl)\b[^\n]{0,40}\/?(home\/[^/\s]+\/)?\.netrc\b/i, severity: 'high', label: 'netrc credentials file exfil' },
  // kubeconfig alternative paths / env-based theft
  // kubectl redacts every credential from `config view` unless `--raw` is given,
  // so the bare form is a harmless "which cluster am I on" and only --raw dumps.
  { pattern: /kubectl\s+config\s+view\b[^\n]{0,120}--raw\b/i, severity: 'high', label: 'kubectl config view (credential dump)' },
  { pattern: /\b(cat|base64|cp|curl)\b[^\n]{0,60}\.kube\/config\b/i, severity: 'high', label: 'kubeconfig file direct read/copy' },
  // High-signal secret formats in exfil context
  { pattern: /AKIA[0-9A-Z]{16}[^\n]{0,120}(curl|wget|nc|POST|exfil)/i, severity: 'critical', label: 'AWS AKIA key in exfil context' },
  { pattern: /ghp_[A-Za-z0-9]{36}[^\n]{0,120}(curl|wget|nc|POST)/i, severity: 'critical', label: 'GitHub PAT in exfil context' },
  { pattern: /xoxb-[A-Za-z0-9-]{40,}/i, severity: 'high', label: 'Slack bot token detected' },
  { pattern: /xoxp-[A-Za-z0-9-]{40,}/i, severity: 'high', label: 'Slack user OAuth token detected' },
  { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'high', label: 'OpenSSH private key block detected' },
  { pattern: /sq0csp-[A-Za-z0-9_-]{40,}/i, severity: 'high', label: 'Square OAuth secret detected' },
  // An Account SID is a public account identifier that ships in client config and
  // URLs — it authenticates nothing on its own, so it is an FYI, not a leak.
  { pattern: /AC[0-9a-f]{32}/, severity: 'low', label: 'Twilio Account SID detected' },
  { pattern: /SK[0-9a-f]{32}/, severity: 'high', label: 'Twilio API key detected' },
  // ─────────────────────────────────────────────────────────────────────────────
  // Category: Cloud metadata SSRF & cloud-account abuse
  // ─────────────────────────────────────────────────────────────────────────────
  // IMDSv1/v2 endpoint access — all forms
  { pattern: /169\.254\.169\.254/i, severity: 'high', label: 'Cloud IMDS IP (169.254.169.254) accessed' },
  { pattern: /fd00:ec2::254/i, severity: 'high', label: 'AWS IMDSv2 IPv6 endpoint accessed' },
  { pattern: /metadata\.google\.internal/i, severity: 'high', label: 'GCP metadata server accessed' },
  { pattern: /metadata\.azure\.internal/i, severity: 'high', label: 'Azure IMDS internal endpoint accessed' },
  { pattern: /169\.254\.169\.254\/[^\s]{0,80}(iam|security-credentials|access-key|token)/i, severity: 'high', label: 'IMDS IAM credential endpoint queried' },
  { pattern: /X-aws-ec2-metadata-token[-\w]*\s*:/i, severity: 'high', label: 'IMDSv2 token header present (SSRF probe)' },
  { pattern: /curl\b[^\n]{0,60}169\.254\.169\.254/i, severity: 'high', label: 'curl to IMDS endpoint' },
  { pattern: /wget\b[^\n]{0,60}169\.254\.169\.254/i, severity: 'high', label: 'wget to IMDS endpoint' },
  { pattern: /http:\/\/169\.254\.169\.254\/latest\/meta-data/i, severity: 'high', label: 'AWS IMDS metadata path fetched' },
  { pattern: /http:\/\/169\.254\.169\.254\/latest\/dynamic\/instance-identity/i, severity: 'high', label: 'AWS IMDS instance identity document fetched' },
  // AWS CLI account/identity enumeration.
  // get-caller-identity is the AWS `whoami` and list-* is read-only: both are
  // routine reconnaissance a developer runs constantly. Kept for the timeline,
  // tiered low so they do not crowd out the mutating calls just below.
  { pattern: /aws\s+sts\s+get-caller-identity/i, severity: 'low', label: 'AWS STS get-caller-identity (account enum)' },
  { pattern: /aws\s+iam\s+list-(users|roles|groups|policies|access-keys)\b/i, severity: 'low', label: 'AWS IAM enumeration' },
  { pattern: /aws\s+iam\s+create-access-key/i, severity: 'high', label: 'AWS IAM access key creation' },
  { pattern: /aws\s+iam\s+attach-(user|role|group)-policy/i, severity: 'high', label: 'AWS IAM policy attachment' },
  { pattern: /aws\s+sts\s+assume-role\b/i, severity: 'high', label: 'AWS STS assume-role (privilege escalation)' },
  { pattern: /aws\s+sts\s+assume-role-with-web-identity/i, severity: 'high', label: 'AWS STS assume-role-with-web-identity' },
  { pattern: /aws\s+organizations\s+list-(accounts|roots|policies)\b/i, severity: 'high', label: 'AWS Organizations account enumeration' },
  { pattern: /aws\s+ec2\s+describe-(instances|security-groups|vpcs|subnets)\b/i, severity: 'medium', label: 'AWS EC2 infrastructure enumeration' },
  { pattern: /aws\s+s3\s+cp\b[^\n]{0,80}(s3:\/\/|http)/i, severity: 'medium', label: 'AWS S3 copy (potential exfil)' },
  // GCP CLI abuse
  // Printing an access token is the documented way to authenticate a docker login
  // against GCR/Artifact Registry, so on its own it is routine; the critical tier
  // still catches the token being paired with a network sink.
  { pattern: /gcloud\s+auth\s+print-access-token/i, severity: 'low', label: 'GCP access token printed to stdout' },
  { pattern: /gcloud\s+auth\s+print-identity-token/i, severity: 'high', label: 'GCP identity token printed to stdout' },
  { pattern: /gcloud\s+iam\s+service-accounts\s+(keys\s+create|list)\b/i, severity: 'high', label: 'GCP service account key creation/list' },
  { pattern: /gcloud\s+projects\s+list\b/i, severity: 'medium', label: 'GCP project enumeration' },
  { pattern: /gcloud\s+compute\s+instances\s+list\b/i, severity: 'medium', label: 'GCP compute instance enumeration' },
  // Azure CLI. The read-only calls (token print, directory enumeration, reading a
  // vault secret a developer is already entitled to, blob I/O) are everyday work
  // and sit low; `role assignment create` GRANTS access and stays high.
  { pattern: /az\s+account\s+get-access-token/i, severity: 'low', label: 'Azure access token retrieved via az cli' },
  { pattern: /az\s+ad\s+(user|group|sp)\s+list\b/i, severity: 'low', label: 'Azure AD identity enumeration' },
  { pattern: /az\s+role\s+assignment\s+(create|list)\b/i, severity: 'high', label: 'Azure role assignment manipulation' },
  { pattern: /az\s+keyvault\s+secret\s+(show|list|download)\b/i, severity: 'low', label: 'Azure Key Vault secret access' },
  { pattern: /az\s+storage\s+(blob|account)\s+(upload|download|list)\b/i, severity: 'low', label: 'Azure storage access (potential exfil)' },
  // Generic SSRF probes to internal metadata ranges
  { pattern: /http:\/\/192\.168\.\d{1,3}\.\d{1,3}\/[^\s]{0,80}(metadata|credential|token|iam)/i, severity: 'medium', label: 'RFC-1918 metadata SSRF probe' },
  { pattern: /http:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}\/[^\s]{0,80}(metadata|credential|token|iam)/i, severity: 'medium', label: 'RFC-1918 10.x metadata SSRF probe' },
  { pattern: /\bIMDS\b[^\n]{0,60}(token|credential|role)/i, severity: 'medium', label: 'IMDS token/credential reference' },
  // Supply-chain attacks
  { pattern: /npm\s+install\s+https?:\/\//i, severity: 'high', label: 'npm install from raw HTTP/S URL' },
  { pattern: /npm\s+install\s+git\+https?:\/\//i, severity: 'high', label: 'npm install from git+http(s) URL' },
  { pattern: /npm\s+install\s+git\+ssh:\/\/[^@\s]*@(?!github\.com|gitlab\.com|bitbucket\.org)/i, severity: 'medium', label: 'npm install from untrusted git+ssh host' },
  { pattern: /pip\s+install\s+https?:\/\/raw\.githubusercontent\.com/i, severity: 'high', label: 'pip install from raw GitHub URL' },
  { pattern: /pip\s+install\s+https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/i, severity: 'medium', label: 'pip install from non-PyPI HTTP URL' },
  { pattern: /"(?:post|pre)install"\s*:\s*"[^"]*(?:curl|wget|fetch)[^"]*\|\s*(?:sh|bash|node)"/i, severity: 'high', label: 'postinstall/preinstall script piping to shell' },
  { pattern: /curl\s+[^\s]+\s*\|\s*npm/i, severity: 'high', label: 'curl piped into npm' },
  { pattern: /wget\s+[^\s]+\s*\|\s*npm/i, severity: 'high', label: 'wget piped into npm' },
  { pattern: /npm\s+config\s+set\s+registry\s+https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/i, severity: 'high', label: 'npm registry set to untrusted host' },
  { pattern: /yarn\s+config\s+set\s+registry\s+https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)/i, severity: 'high', label: 'yarn registry set to untrusted host' },
  { pattern: /gem\s+install\s+--source\s+https?:\/\/(?!rubygems\.org)/i, severity: 'high', label: 'gem install from non-rubygems source' },
  { pattern: /gem\s+install\s+https?:\/\//i, severity: 'high', label: 'gem install from raw URL' },
  { pattern: /go\s+install\s+[^\s]*(?:\.xyz|\.top|\.club|\.pw|\.cc)\//i, severity: 'high', label: 'go install from suspicious TLD host' },
  { pattern: /go\s+install\s+[^\s]*@[^\s]*(?:github|gitlab)\.com\/[^\/]+\/[^\/]+\/[^\/]+\//i, severity: 'low', label: 'go install from deeply nested path (potential typosquat)' },
  { pattern: /npx\s+(?:--yes|-y)?\s*https?:\/\//i, severity: 'high', label: 'npx running package from remote URL' },
  { pattern: /npx\s+(?:--yes|-y)?\s+[a-z0-9_-]{1,20}\s+--eval\s+/i, severity: 'medium', label: 'npx remote package with --eval flag' },
  { pattern: /"scripts"\s*:\s*\{[^}]*"(?:prepare|postinstall|preinstall)"\s*:\s*"[^"]*(?:curl|wget|bash|sh|node -e|eval)/i, severity: 'high', label: 'package.json lifecycle script with remote fetch/exec' },
  { pattern: /pip\s+install\s+(?:--index-url|--extra-index-url)\s+https?:\/\/(?!pypi\.org|files\.pythonhosted\.org)/i, severity: 'high', label: 'pip install from untrusted index URL' },
  { pattern: /npm\s+install\s+@[a-z0-9-]+\/[a-z0-9-]+\s+--registry\s+https?:\/\/(?!registry\.npmjs\.org)/i, severity: 'high', label: 'scoped npm package from non-official registry (dependency confusion)' },
  { pattern: /npm\s+publish\s+--registry\s+https?:\/\/(?!registry\.npmjs\.org)/i, severity: 'medium', label: 'npm publish to non-official registry' },
  { pattern: /pip\s+install\s+-e\s+git\+https?:\/\/(?!github\.com|gitlab\.com|bitbucket\.org)/i, severity: 'high', label: 'pip editable install from untrusted git host' },
  { pattern: /curl\s+[^\s]+\s*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i, severity: 'high', label: 'curl piped to shell (script execution)' },
  { pattern: /wget\s+-qO-\s+[^\s]+\s*\|\s*(?:sudo\s+)?(?:bash|sh)\b/i, severity: 'high', label: 'wget piped to shell (script execution)' },
  { pattern: /package-lock\.json[^>]*>\s*\{[^}]*"resolved"\s*:\s*"https?:\/\/(?!registry\.npmjs\.org)/i, severity: 'medium', label: 'package-lock resolved URL from non-official registry (lockfile tamper)' },
  { pattern: /yarn\.lock[^>]*>\s*[^\n]*\n[^\n]*https?:\/\/(?!registry\.yarnpkg\.com|registry\.npmjs\.org)/i, severity: 'medium', label: 'yarn.lock entry with non-official registry URL' },
  { pattern: /npm\s+install\s+[a-z0-9_-]+\s+--save(?:-dev)?\s+.*--registry/i, severity: 'medium', label: 'npm install with explicit registry override' },
  { pattern: /pip\s+install\s+[a-zA-Z0-9_-]+\s*==\s*0\.0\.(?:0|1)\b/i, severity: 'medium', label: 'pip install of version 0.0.x package (possible dependency confusion probe)' },
  { pattern: /npx\s+create-[a-z0-9-]+@latest\s+--template\s+https?:\/\//i, severity: 'high', label: 'npx create-* with remote template URL' },
  { pattern: /python\s+-c\s+"[^"]*(?:urllib|requests)\.get\([^)]*\).*exec\b/i, severity: 'high', label: 'python one-liner fetching and exec-ing remote code' },
  { pattern: /node\s+-e\s+"[^"]*require\(['"]https?:\/\//i, severity: 'high', label: 'node -e requiring remote module URL' },
  { pattern: /pip\s+install\s+--pre\s+[a-zA-Z0-9_-]+\s+--index-url\s+https?:\/\/(?!pypi\.org)/i, severity: 'high', label: 'pip install pre-release from untrusted index' },
  { pattern: /npm\s+i\s+https?:\/\//i, severity: 'high', label: 'npm i (short) from raw HTTP/S URL' },
  // Container & k8s escape
  { pattern: /docker\s+run\s+[^\n]*--privileged/i, severity: 'high', label: 'docker run with --privileged flag' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/:\//i, severity: 'high', label: 'docker run mounting host root filesystem' },
  { pattern: /docker\s+run\s+[^\n]*--volume\s+\/:\//i, severity: 'high', label: 'docker run --volume mounting host root' },
  { pattern: /\/var\/run\/docker\.sock/i, severity: 'high', label: 'Docker socket access or mount (/var/run/docker.sock)' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/var\/run\/docker\.sock/i, severity: 'high', label: 'docker run mounting Docker socket into container' },
  // Shelling into your own pod is the single most-typed kubectl command in normal
  // debugging; it is worth recording but not worth an alert on its own. The
  // higher-tier variants below still cover exec into kube-system.
  { pattern: /kubectl\s+exec\s+[^\n]*--\s*(?:bash|sh|\/bin\/sh|\/bin\/bash)\b/i, severity: 'low', label: 'kubectl exec spawning shell in pod' },
  { pattern: /kubectl\s+exec\s+-it?\s+[^\n]*--\s*(?:bash|sh)\b/i, severity: 'high', label: 'kubectl exec interactive shell in pod' },
  { pattern: /nsenter\s+(?:-t\s+1|--target\s+1)/i, severity: 'high', label: 'nsenter targeting PID 1 (container escape)' },
  { pattern: /docker\s+run\s+[^\n]*--cap-add[=\s]+SYS_ADMIN/i, severity: 'high', label: 'docker run adding SYS_ADMIN capability' },
  { pattern: /docker\s+run\s+[^\n]*--pid[=\s]+host/i, severity: 'high', label: 'docker run with host PID namespace' },
  { pattern: /docker\s+run\s+[^\n]*--net(?:work)?[=\s]+host[^\n]*(?:exec|bash|sh|nc|curl)/i, severity: 'high', label: 'docker run with host network + command exec' },
  { pattern: /chroot\s+\/host/i, severity: 'high', label: 'chroot into /host (container breakout)' },
  { pattern: /kubectl\s+create\s+clusterrolebinding\s+[^\s]+\s+--clusterrole[=\s]+cluster-admin/i, severity: 'high', label: 'kubectl granting cluster-admin via clusterrolebinding' },
  { pattern: /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\/token/i, severity: 'high', label: 'Kubernetes service-account token access' },
  { pattern: /cat\s+\/var\/run\/secrets\/kubernetes\.io/i, severity: 'high', label: 'Reading Kubernetes service-account secret file' },
  { pattern: /docker\s+run\s+[^\n]*--userns[=\s]+host/i, severity: 'high', label: 'docker run disabling user namespace isolation' },
  { pattern: /docker\s+exec\s+[^\n]*--privileged/i, severity: 'high', label: 'docker exec with --privileged flag' },
  { pattern: /kubectl\s+patch\s+(?:clusterrole|rolebinding|clusterrolebinding)/i, severity: 'high', label: 'kubectl patching RBAC role or binding' },
  { pattern: /kubectl\s+create\s+(?:role|clusterrole)\s+[^\s]+\s+--verb[=\s]+\*/i, severity: 'high', label: 'kubectl creating role with wildcard verbs' },
  { pattern: /docker\s+run\s+[^\n]*--ipc[=\s]+host/i, severity: 'medium', label: 'docker run with host IPC namespace' },
  { pattern: /mount\s+-t\s+proc\s+[^\s]+\s+\/proc\b/i, severity: 'high', label: 'Mounting /proc from inside container' },
  // Applying a manifest straight from a URL is how nearly every add-on documents
  // its install (cert-manager, ingress-nginx, Contour …), so the allowlist covers
  // the release hosts those docs actually point at; anything else is unvetted.
  { pattern: /kubectl\s+apply\s+-f\s+https?:\/\/(?!(?:raw\.githubusercontent\.com|github\.com|objects\.githubusercontent\.com|[a-z0-9-]+\.k8s\.io|storage\.googleapis\.com|charts\.[a-z0-9.-]+)\/)/i, severity: 'medium', label: 'kubectl apply from non-official remote URL' },
  { pattern: /kubectl\s+run\s+[^\n]*--image[=\s]+[^\s]*\s+--command\s+--\s*(?:sh|bash)/i, severity: 'high', label: 'kubectl run ad-hoc pod spawning shell' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/etc[:/]/i, severity: 'high', label: 'docker run mounting host /etc directory' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/root[:/]/i, severity: 'high', label: 'docker run mounting host /root directory' },
  { pattern: /docker\s+run\s+[^\n]*--security-opt[=\s]+seccomp[=:]unconfined/i, severity: 'high', label: 'docker run with seccomp unconfined' },
  { pattern: /docker\s+run\s+[^\n]*--security-opt[=\s]+apparmor[=:]unconfined/i, severity: 'high', label: 'docker run with AppArmor unconfined' },
  { pattern: /kubectl\s+exec\s+[^\n]*-n\s+kube-system/i, severity: 'high', label: 'kubectl exec into kube-system namespace pod' },
  { pattern: /curl\s+[^\s]*kubernetes\.default\.svc/i, severity: 'high', label: 'Accessing Kubernetes API server from inside pod' },
  // Every in-cluster client library reads these env vars, so the bare name is
  // ordinary application code. Reaching the API server through them by hand is
  // the part worth flagging, hence the required fetch verb.
  { pattern: /(?:curl|wget|fetch|nc)\s[^\n]{0,120}KUBERNETES_(?:SERVICE_HOST|PORT_443_TCP)/i, severity: 'medium', label: 'Referencing Kubernetes in-cluster API env vars' },
  { pattern: /docker\s+run\s+[^\n]*--cap-add[=\s]+NET_ADMIN/i, severity: 'medium', label: 'docker run adding NET_ADMIN capability' },
  { pattern: /runc\s+--root\s+\/var\/run\/docker\/runtime/i, severity: 'high', label: 'Direct runc invocation on Docker runtime root' },
  // ── DATA EXFILTRATION ──────────────────────────────────────────────────────
  // curl posting a local file to an external host
  { pattern: /curl\s+[^|]*-d\s+@[\w.\/~-]+\s+https?:\/\/(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i, severity: 'high', label: 'curl POST file to external host' },
  // curl --data-binary @file upload. --data-binary is the standard way to POST a
  // JSON/GraphQL body from a file, so the uploaded file must itself look like
  // credential material for this to mean exfiltration.
  { pattern: /curl\s+[^|\n]{0,160}--data-binary\s+@[\w.\/~-]{0,60}(?:\.env|\.pem\b|\.key\b|id_rsa|id_ed25519|credentials|\.ssh\/|secret|\.p12\b)/i, severity: 'high', label: 'curl --data-binary file upload' },
  // POST to pastebin
  { pattern: /curl\s+[^|]*https?:\/\/pastebin\.com\/(api|raw)/i, severity: 'high', label: 'curl POST to pastebin' },
  // POST to webhook.site
  { pattern: /curl\s+[^|]*https?:\/\/webhook\.site\//i, severity: 'high', label: 'curl exfil to webhook.site' },
  // POST to requestbin / pipedream
  { pattern: /curl\s+[^|]*https?:\/\/(requestbin\.com|pipedream\.net|eo\.requestcatcher\.com)/i, severity: 'high', label: 'curl exfil to requestbin/pipedream' },
  // POST to ngrok tunnel
  { pattern: /curl\s+[^|]*https?:\/\/[\w-]+\.ngrok(\.io|free\.app|\.app)/i, severity: 'high', label: 'curl exfil via ngrok tunnel' },
  // POST to Burp Collaborator
  { pattern: /curl\s+[^|]*https?:\/\/[\w.-]+\.burpcollaborator\.net/i, severity: 'high', label: 'curl exfil to Burp Collaborator' },
  // DNS exfil via nslookup with encoded subdomain
  { pattern: /nslookup\s+[a-zA-Z0-9+\/=]{20,}\.[a-z.-]+/i, severity: 'high', label: 'DNS exfiltration via nslookup (encoded subdomain)' },
  // DNS exfil via dig with encoded subdomain
  { pattern: /dig\s+[+@\w\s]*[a-zA-Z0-9+\/=]{20,}\.[a-z.-]+/i, severity: 'high', label: 'DNS exfiltration via dig (encoded subdomain)' },
  // scp of sensitive dot-files or directories to remote
  { pattern: /scp\s+[^|]*~\/\.(ssh|aws|env|config|gnupg|netrc)\S*\s+\w+@[\w.-]+:/i, severity: 'critical', label: 'scp sensitive dotfile to remote host' },
  // scp of .env or secrets file to remote host
  { pattern: /scp\s+[^|]*\.(env|pem|key|p12|pfx)\s+\w+@[\w.-]+:/i, severity: 'critical', label: 'scp secrets/cert file to remote host' },
  // rsync of sensitive dirs to remote
  { pattern: /rsync\s+[^|]*~\/\.(ssh|aws|gnupg)\s+\w+@[\w.-]+:/i, severity: 'critical', label: 'rsync sensitive dotdir to remote host' },
  // tar piped to curl (archive and upload)
  { pattern: /tar\s+[czjJf]*\s*-?\s*[^|]+\|\s*curl\b/i, severity: 'high', label: 'tar archive piped to curl upload' },
  // base64 encode file then curl/wget
  { pattern: /base64\s+[^|]*\|\s*(curl|wget)\b/i, severity: 'high', label: 'base64 encoded file piped to curl/wget' },
  // base64 encode file then pipe to nc/netcat
  { pattern: /base64\s+[^|]*\|\s*nc\b/i, severity: 'critical', label: 'base64 encoded file piped to netcat' },
  // nc / netcat file transfer outbound with explicit remote host
  { pattern: /nc\s+[^|]*-[we]\s+\d+\s+<\s*[\w.\/~-]+/i, severity: 'critical', label: 'netcat file transfer to remote host' },
  // nc pipe outbound to remote (not localhost)
  { pattern: /\|\s*nc\s+(?!localhost|127\.0\.0\.1)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/i, severity: 'critical', label: 'pipe data to netcat remote IP' },
  // uploading ~/.ssh directory/keys
  { pattern: /curl\s+[^|]*(--data|--upload-file|-T)\s+[^|]*~\/\.ssh\//i, severity: 'critical', label: 'curl upload of ~/.ssh content' },
  // uploading .env file externally
  { pattern: /curl\s+[^|]*(--data|--upload-file|-T|-d)\s+[^|]*\.env\b/i, severity: 'critical', label: 'curl exfil of .env file' },
  // Telegram bot webhook used for exfil
  { pattern: /curl\s+[^|]*https?:\/\/api\.telegram\.org\/bot[\w:]+\/sendMessage/i, severity: 'high', label: 'Telegram bot API used for data exfil' },
  // Discord webhook POST
  { pattern: /curl\s+[^|]*https?:\/\/discord(app)?\.com\/api\/webhooks\//i, severity: 'high', label: 'Discord webhook exfiltration' },
  // Slack webhook POST with data
  { pattern: /curl\s+[^|]*-d\s+[^|]*https?:\/\/hooks\.slack\.com\/services\//i, severity: 'high', label: 'Slack webhook used for data exfil' },
  // wget to upload file to external
  { pattern: /wget\s+[^|]*--post-file=[\w.\/~-]+\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i, severity: 'critical', label: 'wget --post-file exfiltration' },
  // python requests/urllib POST of file content to external
  { pattern: /requests\.(post|put)\s*\([^)]*open\s*\([^)]*\.(env|pem|key|ssh)/i, severity: 'critical', label: 'Python requests POST of sensitive file' },
  // exfil via /dev/tcp bash redirection to remote
  { pattern: /\/dev\/tcp\/(?!localhost|127\.0\.0\.1)[\w.-]+\/\d{2,5}/i, severity: 'high', label: 'bash /dev/tcp outbound connection for exfil' },
  // sftp put of sensitive file to remote
  { pattern: /sftp\s+[^|]*put\s+[^|]*\.(env|pem|key|ssh|p12)\b/i, severity: 'critical', label: 'sftp PUT of secrets/cert file' },
  // curl upload entire home directory tarball
  { pattern: /tar\s+[^|]*~\s+[^|]*\|\s*curl\b/i, severity: 'high', label: 'home directory tarball upload via curl' },
  // xxd/hexdump piped to curl/nc for binary exfil
  { pattern: /(xxd|hexdump)\s+[^|]+\|\s*(curl|nc|wget)\b/i, severity: 'high', label: 'binary hex dump piped to curl/nc exfil' },
  // openssl enc to encrypt then curl
  { pattern: /openssl\s+enc\s+[^|]+\|\s*curl\b/i, severity: 'high', label: 'openssl-encrypted data piped to curl exfil' },
  // python -c base64 encode + upload one-liner
  { pattern: /python[23]?\s+-c\s+["'][^"']*base64[^"']*encode[^"']*open[^"']*["']/i, severity: 'high', label: 'Python one-liner base64 encode + exfil' },
  // aws s3 cp of secrets to public/external bucket
  { pattern: /aws\s+s3\s+cp\s+[^|]*\.(env|pem|key|ssh)\s+s3:\/\//i, severity: 'high', label: 'AWS S3 upload of secrets/cert file' },
  // ── RECON & ENUMERATION ────────────────────────────────────────────────────
  // whoami combined with id (identity enumeration)
  { pattern: /whoami\s*[;&|]+\s*id\b/i, severity: 'medium', label: 'user identity enumeration (whoami + id)' },
  // uname -a full system info
  { pattern: /uname\s+-[aA]/i, severity: 'medium', label: 'system info dump (uname -a)' },
  // reading /etc/shadow (credential file)
  { pattern: /cat\s+\/etc\/shadow/i, severity: 'high', label: 'read /etc/shadow (password hashes)' },
  // SUID binary search
  { pattern: /find\s+[\/\w.-]*\s+(-perm\s+[-\/]?[24]000|-perm\s+[-\/]?u=s)/i, severity: 'medium', label: 'SUID/SGID binary search (privilege escalation recon)' },
  // reading bash_history for credential recon
  { pattern: /cat\s+~\/\.bash_history/i, severity: 'medium', label: 'read .bash_history for credential recon' },
  // reading zsh_history
  { pattern: /cat\s+~\/\.zsh_history/i, severity: 'medium', label: 'read .zsh_history for credential recon' },
  // nmap port scan of internal or any host
  { pattern: /nmap\s+[^|]*(-sS|-sT|-sV|-sC|-A|-O|-p\s*[\d\-,]+)\s+[\d.]+/i, severity: 'medium', label: 'nmap network/port scan' },
  // masscan high-speed scanner
  { pattern: /masscan\s+[^|]+-p\s*[\d,]+\s+[\d.\/]+/i, severity: 'high', label: 'masscan high-speed port scan' },
  // zmap network scanner
  { pattern: /zmap\s+[^|]*-p\s*\d+/i, severity: 'high', label: 'zmap internet-wide port scan' },
  // internal subnet port sweep via bash loop and /dev/tcp
  { pattern: /for\s+\w+\s+in\s+[^;]+;\s*do\s*.*\/dev\/tcp\//i, severity: 'medium', label: 'bash loop internal port sweep via /dev/tcp' },
  // ip addr / ip a for network interface enumeration
  { pattern: /\bip\s+(addr|a|address)\b/i, severity: 'medium', label: 'network interface enumeration (ip addr)' },
  // ifconfig for network enumeration
  { pattern: /\bifconfig\b(?!\s+\w+\s+(up|down))/i, severity: 'low', label: 'network interface listing (ifconfig)' },
  // arp -a for ARP table/network mapping
  { pattern: /arp\s+-[an]/i, severity: 'medium', label: 'ARP table enumeration (network mapping)' },
  // ps aux for process/credential hunting
  { pattern: /ps\s+(aux|ef|eww|-ef)\b/i, severity: 'medium', label: 'full process list dump (credential hunting)' },
  // env / printenv dump
  { pattern: /\benv\b(?:\s*\|\s*grep|\s*>\s*|\s*&&)|\bprintenv\b/i, severity: 'medium', label: 'environment variable dump' },
  // AWS instance metadata endpoint access
  { pattern: /169\.254\.169\.254\/latest\/meta-data/i, severity: 'high', label: 'AWS IMDSv1 metadata endpoint access' },
  // GCP metadata endpoint
  { pattern: /metadata\.google\.internal\/computeMetadata/i, severity: 'high', label: 'GCP instance metadata endpoint access' },
  // Azure IMDS endpoint
  { pattern: /169\.254\.169\.254\/metadata\/instance/i, severity: 'high', label: 'Azure IMDS metadata endpoint access' },
  // getent passwd for user enumeration
  { pattern: /getent\s+passwd/i, severity: 'medium', label: 'getent passwd user enumeration' },
  // sudo -l for sudo privilege listing
  { pattern: /sudo\s+-l\b/i, severity: 'medium', label: 'sudo privilege enumeration (sudo -l)' },
  // crontab listing for persistence/recon
  { pattern: /crontab\s+-l\b/i, severity: 'medium', label: 'crontab listing (persistence recon)' },
  // reading /etc/cron files
  { pattern: /cat\s+\/etc\/cron(tab|\.d\/[\w.-]+)/i, severity: 'medium', label: 'read crontab files for persistence recon' },
  // listing listening ports via ss or netstat
  { pattern: /(ss|netstat)\s+[^|]*(-tlnp|-tuln|-tulnp|-anp|-an)\b/i, severity: 'medium', label: 'listening port enumeration (ss/netstat)' },
  // reading /proc/net/tcp for open connections
  { pattern: /cat\s+\/proc\/net\/(tcp|udp|fib_trie)/i, severity: 'medium', label: 'read /proc/net for network connection recon' },
  // find world-writable files (privilege escalation path)
  { pattern: /find\s+[\/\w.-]*\s+-perm\s+-[o2]w\b/i, severity: 'medium', label: 'world-writable file search (priv-esc recon)' },
  // hostname enumeration
  { pattern: /hostname\s*(-f|--fqdn|-I|-i)\b/i, severity: 'low', label: 'hostname FQDN/IP enumeration' },
  // reading /etc/hosts for internal hostname mapping
  { pattern: /cat\s+\/etc\/hosts(?!\s*\.)/i, severity: 'low', label: 'read /etc/hosts for internal hostname recon' },
  // cat of /etc/os-release for OS fingerprinting
  { pattern: /cat\s+\/etc\/(os-release|issue|debian_version|redhat-release)/i, severity: 'low', label: 'OS version fingerprinting via /etc/os-release' },
  // last / lastlog for login history
  { pattern: /\blastlog\b|\blastb\b|\blast\s+-[aiFnxwR]\b|\blast\s+\d/i, severity: 'medium', label: 'login history enumeration (last/lastlog)' },
  // lsb_release -a for distro info
  { pattern: /lsb_release\s+-[asd]/i, severity: 'low', label: 'distribution info enumeration (lsb_release)' },
  // find home directories with SSH keys
  { pattern: /find\s+\/home\s+[^|]*-name\s+["']?(authorized_keys|id_rsa|id_ed25519)["']?/i, severity: 'high', label: 'search for SSH keys in home directories' },
  // reading /proc/version for kernel info
  { pattern: /cat\s+\/proc\/version\b/i, severity: 'low', label: 'kernel version recon via /proc/version' },
  // category: Prompt Injection / LLM Jailbreak
  { pattern: /ignore\s+(all\s+)?previous\s+instructions/i, severity: 'high', label: 'ignore-previous-instructions injection' },
  { pattern: /ignore\s+(all\s+)?prior\s+instructions/i, severity: 'high', label: 'ignore-prior-instructions injection' },
  { pattern: /disregard\s+your\s+(system\s+)?prompt/i, severity: 'high', label: 'disregard-system-prompt injection' },
  { pattern: /disregard\s+your\s+guidelines/i, severity: 'high', label: 'disregard-guidelines injection' },
  { pattern: /disregard\s+your\s+previous\s+instructions/i, severity: 'high', label: 'disregard-previous-instructions injection' },
  { pattern: /you\s+are\s+now\s+DAN\b/i, severity: 'high', label: 'DAN jailbreak persona injection' },
  { pattern: /developer\s+mode\s+(enabled|activated|on)/i, severity: 'high', label: 'developer-mode jailbreak activation' },
  { pattern: /pretend\s+(that\s+)?you\s+have\s+no\s+(restrictions|guidelines|rules|filters)/i, severity: 'high', label: 'pretend-no-restrictions jailbreak' },
  { pattern: /\bprint\s+your\s+system\s+prompt\b/i, severity: 'high', label: 'system-prompt extraction request' },
  { pattern: /\breveal\s+your\s+system\s+prompt\b/i, severity: 'high', label: 'system-prompt reveal request' },
  { pattern: /\brepeat\s+(the\s+)?text\s+above\b/i, severity: 'high', label: 'repeat-text-above extraction' },
  { pattern: /\brepeat\s+everything\s+(above|before)\b/i, severity: 'high', label: 'repeat-everything-above extraction' },
  { pattern: /\[system\]/i, severity: 'medium', label: 'instruction smuggling via [system] tag' },
  { pattern: /###\s*system\s*###/i, severity: 'medium', label: 'instruction smuggling via ###system### tag' },
  // A bare <system> tag is ordinary prompt scaffolding and appears throughout
  // documentation and test fixtures; the smuggling signal is an override verb
  // riding inside the tag.
  { pattern: /<system>[^\n]{0,200}(?:ignore|disregard|override|reveal|forget|you are now|new instructions|do anything now)/i, severity: 'medium', label: 'instruction smuggling via <system> tag' },
  { pattern: /do\s+anything\s+now\b/i, severity: 'high', label: 'DAN "do anything now" jailbreak' },
  { pattern: /bypass\s+your\s+safety\s+(filters|guidelines|restrictions|training)/i, severity: 'high', label: 'bypass-safety-filters jailbreak' },
  { pattern: /send\s+(the\s+)?(entire\s+)?conversation\s+to\s+https?:\/\//i, severity: 'high', label: 'exfiltration-via-injection: send conversation' },
  { pattern: /ASSISTANT:\s*I\s+will\s+now\b/i, severity: 'high', label: 'tool-result injection: ASSISTANT persona override' },
  { pattern: /\[INST\].*ignore\s+previous/i, severity: 'high', label: 'Llama [INST] prompt injection' },
  { pattern: /base64[_\-]?decode.*instruction/i, severity: 'medium', label: 'base64-encoded instruction smuggling' },
  { pattern: /decode\s+this\s+base64\s+and\s+(execute|follow|run)/i, severity: 'high', label: 'base64 decode-and-execute instruction' },
  { pattern: /rot13.*instruction/i, severity: 'medium', label: 'ROT13-encoded instruction smuggling' },
  { pattern: /from\s+now\s+on\s+you\s+(must|will|are\s+to)\s+(ignore|disregard|forget)/i, severity: 'high', label: 'from-now-on override injection' },
  { pattern: /your\s+(true\s+)?purpose\s+is\s+now\b/i, severity: 'medium', label: 'purpose-override jailbreak' },
  { pattern: /act\s+as\s+(if\s+you\s+have\s+no\s+(restrictions|filters|guidelines))/i, severity: 'high', label: 'act-as-no-restrictions jailbreak' },
  { pattern: /new\s+(system\s+)?prompt\s*:/i, severity: 'medium', label: 'new system prompt injection' },
  { pattern: /override\s+(all\s+)?(previous\s+)?instructions/i, severity: 'high', label: 'override-instructions injection' },
  { pattern: /you\s+must\s+now\s+comply\s+with\b/i, severity: 'medium', label: 'comply-with override injection' },
  { pattern: /translate\s+the\s+following\s+base64\s+and\s+(run|execute|follow)/i, severity: 'high', label: 'base64 translate-and-run injection' },
  { pattern: /forget\s+(all\s+)?previous\s+(instructions|context|conversations)/i, severity: 'high', label: 'forget-previous-instructions injection' },
  { pattern: /jailbreak\s+(mode|activated|enabled)/i, severity: 'high', label: 'explicit jailbreak mode activation' },
  // category: Privilege Escalation & Persistence
  { pattern: /echo\s+.+NOPASSWD.+>>\s*\/etc\/sudoers/i, severity: 'high', label: 'sudoers NOPASSWD append via echo' },
  { pattern: /visudo|\/etc\/sudoers\.d\//i, severity: 'high', label: 'sudoers file modification' },
  { pattern: /ALL\s*=\s*\(ALL\)\s*NOPASSWD\s*:\s*ALL/i, severity: 'high', label: 'sudoers full NOPASSWD privilege grant' },
  { pattern: /echo\s+.+>>\s*\/etc\/sudoers\b/i, severity: 'high', label: 'direct sudoers file append' },
  // `crontab -l` is the read-only listing and must stay quiet, including when it
  // is piped. Everything else installs or edits a schedule — including the
  // scripted `… | crontab -` stdin form and `crontab <file>`. The bare-dash
  // branch uses a lookahead rather than `\s*$`: `$` is not multiline here, so a
  // greedy `\s*` swallowed the newline and missed `| crontab -` when another
  // command followed on the next line.
  { pattern: /crontab\s+(?:-[^l\s]\S*|-(?=\s|$)|[~.\/]\S*)/i, severity: 'high', label: 'crontab modification (non-list)' },
  { pattern: /echo\s+.+>>\s*\/etc\/cron\./i, severity: 'high', label: 'cron file append for persistence' },
  { pattern: /echo\s+.+>>\s*\/var\/spool\/cron\//i, severity: 'high', label: 'cron spool append for persistence' },
  { pattern: /systemctl\s+enable\s+\S+\s*&&\s*systemctl\s+start/i, severity: 'medium', label: 'systemd service enable+start (persistence)' },
  { pattern: /\bcp\s+\S+\s+\/etc\/systemd\/system\/\S+\.service\b/i, severity: 'high', label: 'dropping new systemd service file' },
  { pattern: /echo\s+.+>>\s*~?\/\.ssh\/authorized_keys/i, severity: 'high', label: 'SSH authorized_keys append (backdoor)' },
  { pattern: /cat\s+.+>>\s*~?\/\.ssh\/authorized_keys/i, severity: 'high', label: 'SSH authorized_keys append via cat' },
  { pattern: /echo\s+.+>>\s*\/etc\/passwd\b/i, severity: 'high', label: '/etc/passwd append (backdoor user)' },
  { pattern: /chmod\s+(u\+s|[0-9]*[4-7][0-9][0-9][0-9])\s+\S+/i, severity: 'high', label: 'setuid bit set on file' },
  { pattern: /chmod\s+(g\+s|[0-9]*[0-9][2-3][0-9][0-9])\s+\S+/i, severity: 'medium', label: 'setgid bit set on file' },
  { pattern: /\bLD_PRELOAD\s*=\s*[^\s]/i, severity: 'high', label: 'LD_PRELOAD shared-library injection' },
  { pattern: /\binsmod\s+\S+\.ko\b/i, severity: 'high', label: 'kernel module loaded via insmod' },
  // Loading a stock in-tree module is standard host prep (`modprobe br_netfilter`
  // is required on every Kubernetes node), unlike insmod against a loose .ko.
  { pattern: /\bmodprobe\s+(?!--remove|--show|-r\b)\S+/i, severity: 'low', label: 'suspicious kernel module load via modprobe' },
  // Appending to a login shell rc file is how tools install themselves — PATH and
  // init-hook exports are the overwhelmingly common case. What distinguishes a
  // backdoor is a network or exec primitive inside the line being persisted, so
  // the payload must carry one to reach this tier. Plain appends are still
  // recorded by the writer-agnostic rule further below.
  // `nc`/`ncat` carry a left word boundary: without it the bare `nc\s` matches
  // inside ordinary words (`resync `, `sync `), so a harmless alias append would
  // be reported as a backdoor.
  { pattern: /echo\s+[^\n]{0,200}?(?:curl\s|wget\s|\bnc\s|\bncat\s|\/dev\/tcp|base64\s+(?:-d|--decode)|bash\s+-i|sh\s+-i|python[0-9]?\s+-c|perl\s+-e)[^\n]{0,200}?>>\s*~?\/\.bashrc\b/i, severity: 'high', label: '.bashrc backdoor append' },
  { pattern: /echo\s+[^\n]{0,200}?(?:curl\s|wget\s|\bnc\s|\bncat\s|\/dev\/tcp|base64\s+(?:-d|--decode)|bash\s+-i|sh\s+-i|python[0-9]?\s+-c|perl\s+-e)[^\n]{0,200}?>>\s*~?\/\.bash_profile\b/i, severity: 'high', label: '.bash_profile backdoor append' },
  { pattern: /echo\s+[^\n]{0,200}?(?:curl\s|wget\s|\bnc\s|\bncat\s|\/dev\/tcp|base64\s+(?:-d|--decode)|bash\s+-i|sh\s+-i|python[0-9]?\s+-c|perl\s+-e)[^\n]{0,200}?>>\s*~?\/\.profile\b/i, severity: 'high', label: '.profile backdoor append' },
  { pattern: /launchctl\s+load\s+\S+\.plist/i, severity: 'high', label: 'launchd plist loaded for persistence (macOS)' },
  { pattern: /cp\s+\S+\s+~?\/Library\/LaunchAgents\//i, severity: 'high', label: 'LaunchAgent plist dropped (macOS persistence)' },
  { pattern: /cp\s+\S+\s+\/Library\/LaunchDaemons\//i, severity: 'high', label: 'LaunchDaemon plist dropped (macOS persistence)' },
  { pattern: /echo\s+.+>>\s*\/etc\/ld\.so\.preload/i, severity: 'high', label: '/etc/ld.so.preload backdoor append' },
  { pattern: /chmod\s+4[0-9]{3}\s+\S+/i, severity: 'high', label: 'setuid octal chmod (e.g., 4755)' },
  { pattern: /\/etc\/init\.d\/\S+\s+(enable|start)|update-rc\.d\s+\S+\s+enable/i, severity: 'medium', label: 'SysV init service persistence' },
  { pattern: /at\s+now\s+<<\s*EOF/i, severity: 'medium', label: 'at-job scheduled command (persistence)' },
  { pattern: /echo\s+[^\n]{0,200}?(?:curl\s|wget\s|nc\s|ncat\s|\/dev\/tcp|base64\s+(?:-d|--decode)|bash\s+-i|sh\s+-i|python[0-9]?\s+-c|perl\s+-e)[^\n]{0,200}?>>\s*~?\/\.zshrc\b/i, severity: 'high', label: '.zshrc backdoor append' },
  // Writer-agnostic companion to the three rules above: `echo` is only one way to
  // append to a startup file — `cat payload >> ~/.bashrc` and
  // `tee -a ~/.bashrc < payload` achieve the same persistence and were invisible.
  // Any write to a login-shell startup file is worth a timeline entry, so this
  // one keys on the TARGET rather than the payload and sits a tier lower; the
  // rules above still escalate when the appended line carries a live payload.
  { pattern: /(?:>>\s*|\btee\s+(?:-a|--append)\s+)['"]?[^\s'"|;&]{0,60}(?:\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|kshrc)\b|config\.fish\b|\/profile\.d\/|\/etc\/(?:profile|bashrc|zshrc|zshenv)\b)/i, severity: 'medium', label: 'shell startup file written (persistence surface)' },
  { pattern: /\bptrace\b.*PTRACE_ATTACH/i, severity: 'high', label: 'ptrace ATTACH (process injection)' },
  { pattern: /\/proc\/[0-9]+\/mem\b/i, severity: 'high', label: 'direct /proc/PID/mem access (process memory write)' },
  { pattern: /echo\s+.+>>\s*\/root\/\.ssh\/authorized_keys/i, severity: 'high', label: 'root SSH authorized_keys append' },

  // ─────────────────────────────────────────────────────────────────────────────
  // Category: ClaudeSec self-protection (the monitor's own control plane)
  // ─────────────────────────────────────────────────────────────────────────────
  // A security tool that cannot notice being switched off has a hole underneath
  // everything else it claims. The PreToolUse hook refuses these writes before
  // they run, but the hook only ever sees a tool call: a raw `fs.writeFile` from
  // a script the agent launched, an edit made while CLAUDESEC_HOOKS_BYPASS was
  // set, or a write from any process that is not the agent, all reach the disk
  // unseen. These rules are the post-hoc half, so the attempt still lands on the
  // timeline with an alert even when no hook was in the path.
  //
  // Every pattern is anchored on the WRITE, never on the filename. `settings.json`
  // and `enforce-config.json` are named constantly in ordinary work — read,
  // grepped, quoted in a commit message, listed in a diff — and a rule that fires
  // on `cat .claude/settings.json` would be worse than no rule at all. So each one
  // requires a redirect (`>`/`>>`), a mutating command (tee, rm, mv, cp, install,
  // truncate, shred, chmod, ln …), an in-place editor (`sed -i`, `perl -pi`), or
  // an inline interpreter script, with the control-plane path as its target.
  //
  // The tool-call rule leads because it is the most specific: it keys on the
  // file_path of a Write/Edit span sitting next to a content-bearing key, which a
  // Read span never carries.
  { pattern: /"file_path"\s*:\s*"[^"\n]{0,160}(?:\.claude\/settings(?:\.local)?\.json|\.claude\/hooks\/|\.claudesec\/hooks\/|enforce-config\.json|rules-enforcement\.json|claudesec-enforce\.cjs)[^"\n]{0,40}"\s*,\s*"(?:content|old_string|new_string|edits|new_source)"/i, severity: 'high', label: 'ClaudeSec control-plane file written by an agent tool call' },
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}enforce-config\.json|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync)\b[^\n;&|]{0,120}enforce-config\.json|\bsed\b[^\n;&|]{0,20}-i[^\n;&|]{0,100}enforce-config\.json|\b(?:python[0-9.]*|node|deno|perl|ruby)\b[^\n;&|]{0,30}\s-(?:c|e|pi)\b[^\n]{0,200}enforce-config\.json)/i, severity: 'high', label: 'ClaudeSec enforcement config overwritten (enforce-config.json)' },
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}rules-enforcement\.json|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync)\b[^\n;&|]{0,120}rules-enforcement\.json|\bsed\b[^\n;&|]{0,20}-i[^\n;&|]{0,100}rules-enforcement\.json|\b(?:python[0-9.]*|node|deno|perl|ruby)\b[^\n;&|]{0,30}\s-(?:c|e|pi)\b[^\n]{0,200}rules-enforcement\.json)/i, severity: 'high', label: 'ClaudeSec rule snapshot overwritten (rules-enforcement.json)' },
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}(?:claudesec-enforce\.cjs|\.claudesec\/hooks\/|protected-paths\.json)|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync)\b[^\n;&|]{0,120}(?:claudesec-enforce\.cjs|\.claudesec\/hooks\/|protected-paths\.json)|\bsed\b[^\n;&|]{0,20}-i[^\n;&|]{0,100}(?:claudesec-enforce\.cjs|\.claudesec\/hooks\/|protected-paths\.json)|\b(?:python[0-9.]*|node|deno|perl|ruby)\b[^\n;&|]{0,30}\s-(?:c|e|pi)\b[^\n]{0,200}(?:claudesec-enforce\.cjs|\.claudesec\/hooks\/|protected-paths\.json))/i, severity: 'high', label: 'ClaudeSec enforcement hook or artefact directory modified' },
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}\.claude\/(?:settings(?:\.local)?\.json|hooks\/)|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync)\b[^\n;&|]{0,120}\.claude\/(?:settings(?:\.local)?\.json|hooks\/)|\bsed\b[^\n;&|]{0,20}-i[^\n;&|]{0,100}\.claude\/(?:settings(?:\.local)?\.json|hooks\/)|\b(?:python[0-9.]*|node|deno|perl|ruby)\b[^\n;&|]{0,30}\s-(?:c|e|pi)\b[^\n]{0,200}\.claude\/(?:settings(?:\.local)?\.json|hooks\/))/i, severity: 'high', label: 'Claude Code hook registration modified (.claude/settings.json)' },
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}\.claudesec\/(?:audit-key|audit-anchor\.json)|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync)\b[^\n;&|]{0,120}\.claudesec\/(?:audit-key|audit-anchor\.json)|\bsed\b[^\n;&|]{0,20}-i[^\n;&|]{0,100}\.claudesec\/(?:audit-key|audit-anchor\.json))/i, severity: 'high', label: 'ClaudeSec audit signing key or anchor tampered with' },
  // The launchd plist / systemd unit is what restarts the collector after a
  // reboot; rewriting or deleting it is a durable way to keep it down.
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}|\b(?:tee|rm|mv|cp|install|truncate|shred|unlink|chmod|chown|chattr|chflags|ln|ditto|rsync|plutil|defaults)\b[^\n;&|]{0,120})(?:Launch(?:Agents|Daemons)\/[^\s/'"]{0,60}claudesec[^\s/'"]{0,30}\.plist|systemd\/[^\s/'"]{0,30}\/[^\s/'"]{0,40}claudesec[^\s/'"]{0,30}\.(?:service|timer))/i, severity: 'high', label: 'ClaudeSec service definition (launchd plist / systemd unit) modified' },
  // Stopping the collector by label rather than by file — none of these name the
  // unit file, and all of them end the recording just as effectively.
  { pattern: /\b(?:launchctl\s+(?:unload|bootout|disable|remove|kill)|systemctl(?:\s+--user)?\s+(?:stop|disable|mask)|pkill\s+(?:-\S{1,8}\s+){0,3}|killall\s+(?:-\S{1,8}\s+){0,2})[^\n;&|]{0,120}claudesec/i, severity: 'high', label: 'ClaudeSec service stopped or disabled' },
  // The tool's own teardown commands. Inside an agent session these never run:
  // the self-protection floor refuses `claudesec uninstall-hook`, `uninstall`
  // and `stop` in every mode, precisely so an agent cannot switch off the thing
  // watching it. But the floor only sees what an agent submits. Run in a plain
  // terminal — the supported, legitimate way to remove the tool — the same
  // command left NO trace anywhere: no alert, no audit row, nothing to answer
  // "when did enforcement stop?" with.
  //
  // Deliberately `medium`, not `high`. High and critical bake to `action: block`
  // in the enforcement snapshot, and the only population this rule can still
  // reach is the operator uninstalling software they own on a machine they
  // control. Refusing that would be both wrong and futile — they can uninstall
  // it without an agent in the room. The requirement here is the record, not the
  // refusal, and `medium` puts the event in the alert feed and the audit trail
  // where an incident timeline can find it.
  //
  // The subcommand must follow the binary, so `grep uninstall-hook README.md`
  // and prose about the command stay silent; the optional runner prefix covers
  // the ways the CLI is actually reached (`npx`, `pnpm exec`, an absolute path,
  // or `node cli/init.mjs` straight out of a checkout).
  { pattern: /(?:^|[\n;&|`(]\s*|\s)(?:(?:npx|bunx|sudo|node|tsx|pnpm|yarn|npm)\s+(?:exec\s+|dlx\s+|run\s+)?)?(?:[^\s;&|'"]{0,80}\/)?(?:claudesec|init\.m?[jt]s)\s+(?:uninstall-hook|uninstall|stop)\b/i, severity: 'medium', label: 'ClaudeSec enforcement uninstalled or stopped from the shell' },
  // Enforcement disabled for a whole command via the environment. The hook records
  // its own bypasses, but a bypass exported for a SCRIPT never reaches the hook.
  // The lead must be a separator, a quote (a serialised `"command":"VAR=1 …"`), or
  // export/env — never a bare space, so prose that merely documents the variable
  // ("Bypass: CLAUDESEC_HOOKS_BYPASS=1") stays silent.
  { pattern: /(?:^|[\n;&|"]|\bexport\s+|\benv\s+)\s*CLAUDESEC_(?:HOOKS_BYPASS|DISABLE_SCRUB)\s*=\s*1\b/, severity: 'medium', label: 'ClaudeSec enforcement or scrubbing disabled via environment' },

  // ── CRITICAL: active secret EXFILTRATION (credential transmitted off-machine) ──
  // A secret merely present in a file stays 'high'; these patterns each pair a
  // credential / .env / private key with a NETWORK SINK (pipe to curl|wget|nc,
  // scp/rsync/sftp to a remote, requests.post, or a literal key in a POST body).
  // .env.example is conventionally non-secret and is deliberately NOT matched:
  // suffix groups enumerate real env variants (no "example") and a boundary char
  // is consumed after the path so "cat .env.example | curl" cannot fire.
  { pattern: /\.aws\/credentials\b[^|\n]{0,60}\|\s*(curl|wget|nc|ncat)\b/i, severity: 'critical', label: 'AWS credentials file piped to network sink' },
  { pattern: /\b(cat|base64|strings|xxd)\b[^|\n]{0,40}(id_(rsa|ed25519|ecdsa|dsa)|\.pem)\b[^|\n]{0,20}\|\s*(curl|wget|nc|ncat)\b/i, severity: 'critical', label: 'SSH private key / PEM piped to network sink' },
  { pattern: /curl\s+[^|\n]{0,160}(-d|--data(-raw|-binary)?)\s+[^|\n]{0,80}(AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{8,40}|ghp_[A-Za-z0-9]{20,40}|AIza[0-9A-Za-z_-]{20,40})[^|\n]{0,120}https?:\/\/(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i, severity: 'critical', label: 'API key literal in curl POST to external host' },
  { pattern: /rsync\s+[^|\n]{0,80}\.env(\.(local|production|prod|staging))?[\s'"][^|\n]{0,40}[\w.-]+@[\w.-]+:/i, severity: 'critical', label: '.env file rsync to remote host' },
  { pattern: /base64\s+[^|\n]{0,60}(\.env|id_(rsa|ed25519|ecdsa|dsa)|\.pem|credentials)\b[^|\n]{0,40}\|\s*(curl|wget)\b/i, severity: 'critical', label: 'credential file base64-piped to curl/wget' },
  { pattern: /curl\s+[^|\n]{0,200}-----BEGIN\s[A-Z ]{0,30}PRIVATE KEY-----/i, severity: 'critical', label: 'private key PEM in curl POST body' },
  { pattern: /open\s*\(\s*['"][^'"\n]{0,80}(\.env|credentials|id_rsa|\.pem)[^'"\n]{0,20}['"][^\n]{0,200}(requests\.(post|put)|urllib\.request\.urlopen|urlopen)\s*\(/i, severity: 'critical', label: 'Python reads credential file then POSTs to network' },
  { pattern: /\bcat\s+[^|\n]{0,40}\.env(\.(local|production|prod|dev|staging))?[\s'";>][^|\n]{0,20}\|\s*(curl|wget|nc|ncat)\b/i, severity: 'critical', label: '.env file read piped to network sink' },
  { pattern: /curl\s+[^|\n]{0,80}(--upload-file|-T)\s+[^|\n]{0,60}(id_(rsa|ed25519|ecdsa|dsa)|\.pem)\b/i, severity: 'critical', label: 'curl upload of SSH private key / PEM' },

  // ─────────────────────────────────────────────────────────────────────────────
  // Category: staging, persistence and evasion primitives
  // ─────────────────────────────────────────────────────────────────────────────
  // The exfiltration rules above all describe a single step: a credential is read
  // and transmitted in the same command. Real theft rarely looks like that. The
  // credential is COPIED somewhere unremarkable first, and the harmless-looking
  // copy leaves later — by which point the outbound half carries no credential
  // shape at all and nothing here can see it. The two staging rules below close
  // that half, and the rest of the block covers execution primitives that the
  // engine could name but had no pattern for.
  //
  // Every one of these is anchored on the dangerous TARGET, never on the verb.
  // `cp -r`, `tar` and `pkill` are among the most common commands in ordinary
  // work — 22, 12 and 173 occurrences respectively in the local history these
  // patterns were tuned against — so a verb-anchored rule would fire on routine
  // builds all day and be worse than no rule at all.

  // Staging, part 1: the whole credential STORE copied somewhere else. A single
  // key file is already covered ('SSH private key file access', 'AWS credentials
  // file read'), but the directory as a unit was not: `cp -r ~/.ssh /tmp/x` and
  // `cp -r ~/.aws /tmp/x` both scored `none`. The path must be the complete
  // argument — a trailing filename or a `.sshconfig`-style suffix does not match,
  // so `cp ~/.ssh/id_rsa.pub authorized_keys` is left to the file-level rules —
  // and a destination argument is required, so `ls`-style inspection is untouched.
  // Blocking tier: copying an entire credential store to an unrelated path has no
  // benign form, and the copy is what makes the later exfil unrecognisable.
  { pattern: /\b(?:cp|mv|ditto|cpio|rsync)\b(?:\s+-{1,2}[A-Za-z][\w-]{0,14}){0,4}\s+['"]?(?:[\w.$~-]{0,40}(?:\/[\w.$-]{1,24}){0,4}\/)?\.(?:ssh|aws|gnupg|kube|azure|config\/gcloud)\/?['"]?(?=\s+\S)/i, severity: 'high', label: 'Credential store directory copied to another path' },

  // Staging, part 2: the same move by archive. `tar czf keys.tgz ~/.ssh` produces
  // one innocuous-looking file that can be uploaded hours later as a "build
  // artefact". The archive verbs are deliberately broad (tar/zip/7z/zstd/pax)
  // because the target carries the whole signal: over the local history every
  // real archive command operated on `dist/`, a release tarball or a downloaded
  // `.tgz`, and not one named a credential directory.
  { pattern: /\b(?:tar|gtar|bsdtar|zip|7z|7za|zstd|pax)\b[^\n;&|]{0,120}?[\s'"=](?:[\w.$~-]{0,40}(?:\/[\w.$-]{1,24}){0,4}\/)?\.(?:ssh|aws|gnupg|kube|azure|config\/gcloud)(?:\/[^\s'";&|]{0,40})?(?:['"]|\s|$)/i, severity: 'high', label: 'Credential store archived into a tarball/zip' },

  // A git hook is arbitrary code that the developer executes themselves on their
  // next commit, push or checkout — persistence that needs no scheduler and no
  // privilege. Anchored on the WRITE, because reading and linting hooks is normal
  // (`ls -la .git/hooks/`, `bash -n .git/hooks/pre-push`, `chmod +x` on a hook you
  // just installed all appear in ordinary work and must stay silent). The trailing
  // `(?![\w.-])` forces the hook name to end at the match, which is what excludes
  // git's own inert `*.sample` stubs.
  // Alert tier, not blocking: hook installers legitimately write here, and the
  // sequence engine already escalates 'Git hook installed then triggered' to high
  // once a hook-executing git operation follows the write.
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,120}|\b(?:tee|cp|mv|install|ln|ditto|rsync|curl|wget)\b[^\n;&|]{0,120})\.git\/hooks\/[\w-]{1,30}(?![\w.-])/i, severity: 'medium', label: 'Git hook script written (repo-local code execution)' },
  { pattern: /"file_path"\s*:\s*"[^"\n]{0,200}\.git\/hooks\/[\w-]{1,30}"\s*,\s*"(?:content|old_string|new_string|edits|new_source)"/i, severity: 'medium', label: 'Git hook script written by an agent tool call' },

  // The perl reverse shell. The bash, python, ruby and PowerShell forms were all
  // covered; perl was only caught when the command happened to contain both
  // "socket" and "INET" ('Perl socket reverse shell'), which the two most common
  // payloads do not — `perl -MSocket -e '...'` and `perl -e 'use Socket; ...'`
  // both scored `none`. Either the socket module is named on the command line, or
  // the inline script imports it / opens a shell.
  { pattern: /\bperl\b[^\n;|&]{0,60}(?:\s-[A-Za-z]{0,3}M(?:IO::)?Socket[\w:]{0,16}\b|\s-[A-Za-z]{0,3}[eE]\s{0,4}['"][^\n]{0,300}?(?:\buse\s+Socket\b|IO::Socket::INET|\bsockaddr_in\s*\(|\bPF_INET\b|\bexec\s*\(?\s*['"]?\/bin\/(?:ba|z|k)?sh\b))/i, severity: 'high', label: 'perl inline socket/shell one-liner (reverse shell)' },

  // AppleScript is a full execution and automation surface on macOS, and none of
  // it was covered. Three tiers, because `osascript` spans the whole range:
  //   • `do shell script` is `sh -c` by another name — and `with administrator
  //     privileges` is `sudo` with a system password prompt. Blocking tier.
  //   • Driving another application, synthesising keystrokes or putting a
  //     credential prompt on screen is how AppleScript reaches Keychain, Mail and
  //     the browser without touching a file the engine watches. Alert tier.
  //   • Any other inline script is audit-trail only: quitting an app by name is
  //     ordinary automation and appears in the local history exactly that way.
  { pattern: /\bosascript\b[^\n]{0,200}?(?:do\s+shell\s+script|with\s+administrator\s+privileges)/i, severity: 'high', label: 'AppleScript shell execution via osascript' },
  { pattern: /\bosascript\b[^\n]{0,200}?(?:System\s+Events|\bkeystroke\s|display\s+dialog|\bkeychain\b|tell\s+application\s+['"](?:Terminal|iTerm|Mail|Messages|Safari|Google Chrome|Notes|Keychain Access))/i, severity: 'medium', label: 'AppleScript drives another app or prompts the user (osascript)' },
  { pattern: /\bosascript\b(?:\s+-[\w-]{1,12}(?:\s+[\w.:-]{1,20})?){0,3}\s+-e\b/i, severity: 'low', label: 'Inline AppleScript executed via osascript' },

  // `/proc/<pid>/environ` is the process environment — where API tokens live once
  // a service has started. The ordinary way to read it (`env`, `printenv`) is
  // already an alert; reaching for `/proc` instead is the evasive form of the same
  // read, and against another PID it harvests a different process's secrets
  // entirely. No shell workflow reads this file, so it takes the blocking tier
  // alongside the existing `/proc/<pid>/mem` rule.
  { pattern: /\/proc\/(?:self|thread-self|[0-9]{1,7}|\$\{?[A-Za-z_][\w]{0,20}\}?)\/environ\b/i, severity: 'high', label: 'Process environment read via /proc/<pid>/environ' },

  // Killing the collector stops the recording without touching a single file the
  // self-protection rules above watch. Those rules key on the string `claudesec`,
  // which the process name does not have to contain: ClaudeSec's own entrypoint is
  // `tsx server/index.ts`, and an OTLP collector is `otelcol`.
  // Alert tier, and deliberately NOT blocking: over the local history every one of
  // the fifteen matches was the maintainer restarting their own dev server. That
  // is genuinely indistinguishable from an agent silencing the monitor by regex
  // alone — the durable control is the self-protection floor, which can compare
  // the target against the service that is actually running.
  { pattern: /\b(?:pkill|killall|kill)\b[^\n;&|]{0,60}?(?:server\/index\.(?:ts|js|mjs|cjs)|\botelcol[\w-]{0,16}|\botel-collector\b|\bopentelemetry-collector\b)/i, severity: 'medium', label: 'Observability collector process killed by name' },
];
