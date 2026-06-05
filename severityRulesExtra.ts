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

export type ExtraSeverity = 'low' | 'medium' | 'high';

export interface ExtraRule {
  pattern: RegExp;
  severity: ExtraSeverity;
  label: string;
}

export const EXTRA_SEVERITY_RULES: ExtraRule[] = [
  // Destructive filesystem & data destruction
  { pattern: /rm\s+-rf\s+\/(?:etc|var|usr|bin|lib|sbin|boot|sys|opt|srv)\b/i,           severity: 'high',   label: 'rm -rf on critical system directory' },
  { pattern: /rm\s+-rf\s+\/(?:home|root|Users)\b/i,                                      severity: 'high',   label: 'rm -rf on home/root directory' },
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
  { pattern: /DROP\s+DATABASE\s+\w/i,                                                     severity: 'high',   label: 'SQL DROP DATABASE statement' },
  { pattern: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?\w/i,                                    severity: 'high',   label: 'SQL DROP TABLE (with optional IF EXISTS)' },
  { pattern: /DROP\s+SCHEMA\s+(?:IF\s+EXISTS\s+)?\w/i,                                   severity: 'high',   label: 'SQL DROP SCHEMA statement' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+1\s*=\s*1/i,                                 severity: 'high',   label: 'SQL DELETE with always-true WHERE (full wipe)' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+['"1]1['"1]?\s*=\s*['"1]1/i,                severity: 'high',   label: 'SQL injection-style DELETE all rows' },
  { pattern: /UPDATE\s+\w+\s+SET\s+\w+\s*=\s*.*WHERE\s+1\s*=\s*1/i,                     severity: 'high',   label: 'SQL UPDATE with always-true WHERE (full wipe)' },
  { pattern: /TRUNCATE\s+(?:TABLE\s+)?\w+\s+(?:CASCADE|RESTART)/i,                       severity: 'high',   label: 'SQL TRUNCATE with CASCADE or RESTART' },
  { pattern: /DROP\s+TABLE\s+.*CASCADE/i,                                                  severity: 'high',   label: 'SQL DROP TABLE CASCADE' },
  { pattern: /ALTER\s+TABLE\s+\w+\s+DROP\s+CONSTRAINT/i,                                  severity: 'medium', label: 'SQL DROP CONSTRAINT on table' },
  { pattern: /mysqldump\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                               severity: 'high',   label: 'mysqldump piped to network transfer' },
  { pattern: /pg_dump\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                                 severity: 'high',   label: 'pg_dump piped to network transfer' },
  { pattern: /sqlite3\s+.*\.dump\s*\|\s*(?:curl|wget|nc)/i,                               severity: 'high',   label: 'SQLite dump piped to network' },
  { pattern: /mysqldump\s+.*-h\s+\S/i,                                                    severity: 'medium', label: 'mysqldump to remote host' },
  { pattern: /pg_dump\s+.*-h\s+\S/i,                                                      severity: 'medium', label: 'pg_dump to remote host' },
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
  { pattern: /DROP\s+KEYSPACE\s+\w/i,                                                     severity: 'high',   label: 'Cassandra DROP KEYSPACE' },
  { pattern: /DELETE\s+FROM\s+\w+\s+WHERE\s+id\s+(?:IN|NOT\s+IN)\s*\(\s*SELECT/i,        severity: 'medium', label: 'SQL mass DELETE via subquery' },
  { pattern: /influx\s+.*delete\s+.*--bucket/i,                                           severity: 'high',   label: 'InfluxDB bucket delete via CLI' },
  { pattern: /pg_dumpall\s+.*\|\s*(?:curl|wget|nc|ncat)\b/i,                              severity: 'high',   label: 'pg_dumpall piped to network transfer' },
  { pattern: /CALL\s+mysql\.rds_kill_query/i,                                              severity: 'medium', label: 'RDS kill query stored procedure' },
  // category: Remote code execution / download-and-run
  { pattern: /curl\s+[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'curl pipe to shell' },
  { pattern: /curl\s+[^|;&\n]*\|\s*bash\b/i, severity: 'high', label: 'curl pipe to bash' },
  { pattern: /wget\s+[^|;&\n]*\|\s*(?:ba)?sh/i, severity: 'high', label: 'wget pipe to shell' },
  { pattern: /wget\s+[^|;&\n]*\|\s*bash\b/i, severity: 'high', label: 'wget pipe to bash' },
  { pattern: /curl\s+[^|;&\n]*\|\s*python3?/i, severity: 'high', label: 'curl pipe to python' },
  { pattern: /wget\s+[^|;&\n]*\|\s*python3?/i, severity: 'high', label: 'wget pipe to python' },
  { pattern: /curl\s+[^|;&\n]*\|\s*perl\b/i, severity: 'high', label: 'curl pipe to perl' },
  { pattern: /curl\s+[^|;&\n]*\|\s*ruby\b/i, severity: 'high', label: 'curl pipe to ruby' },
  { pattern: /curl\s+[^|;&\n]*\|\s*node\b/i, severity: 'high', label: 'curl pipe to node' },
  { pattern: /wget\s+[^|;&\n]*\|\s*perl\b/i, severity: 'high', label: 'wget pipe to perl' },
  { pattern: /wget\s+[^|;&\n]*\|\s*node\b/i, severity: 'high', label: 'wget pipe to node' },
  { pattern: /curl\s+-[A-Za-z]*[oO][A-Za-z]*\s+\S+\s+http[s]?:\/\//i, severity: 'high', label: 'curl download to file from URL' },
  { pattern: /wget\s+-[A-Za-z]*O\s+\S+\s+http[s]?:\/\//i, severity: 'high', label: 'wget download to file from URL' },
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
  { pattern: /\bcat\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key read via cat' },
  { pattern: /\bcp\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key copy' },
  { pattern: /\bscp\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key remote copy' },
  { pattern: /\bbase64\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key base64 encoding' },
  { pattern: /\bstrings\b[^\n]{0,60}\.ssh\/id_(rsa|ed25519|ecdsa|dsa)\b/, severity: 'high', label: 'SSH private key strings extraction' },
  // /etc/shadow read (the existing rule matches access, add targeted read forms)
  { pattern: /\b(cat|less|more|head|tail|strings|xxd|base64)\b[^\n]{0,40}\/etc\/shadow\b/i, severity: 'high', label: '/etc/shadow direct read' },
  { pattern: /\bunshadow\b/i, severity: 'high', label: 'Unshadow password file (passwd+shadow merge)' },
  { pattern: /john\s+.*--format[^\n]{0,60}shadow/i, severity: 'high', label: 'John-the-Ripper shadow hash crack' },
  // .env exfiltration (read + send patterns not caught by existing dotenv rule)
  { pattern: /\benv\b[^\n]{0,40}\|\s*(curl|wget|nc|ncat|python|ruby)\b/i, severity: 'high', label: '.env / env vars piped to exfil tool' },
  { pattern: /printenv[^\n]{0,60}\|\s*(curl|wget|nc|ncat)\b/i, severity: 'high', label: 'printenv output piped to exfil' },
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
  { pattern: /kubectl\s+config\s+(view|export)\b/i, severity: 'high', label: 'kubectl config view (credential dump)' },
  { pattern: /\b(cat|base64|cp|curl)\b[^\n]{0,60}\.kube\/config\b/i, severity: 'high', label: 'kubeconfig file direct read/copy' },
  // High-signal secret formats in exfil context
  { pattern: /AKIA[0-9A-Z]{16}[^\n]{0,120}(curl|wget|nc|POST|exfil)/i, severity: 'high', label: 'AWS AKIA key in exfil context' },
  { pattern: /ghp_[A-Za-z0-9]{36}[^\n]{0,120}(curl|wget|nc|POST)/i, severity: 'high', label: 'GitHub PAT in exfil context' },
  { pattern: /xoxb-[A-Za-z0-9-]{40,}/i, severity: 'high', label: 'Slack bot token detected' },
  { pattern: /xoxp-[A-Za-z0-9-]{40,}/i, severity: 'high', label: 'Slack user OAuth token detected' },
  { pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'high', label: 'OpenSSH private key block detected' },
  { pattern: /sq0csp-[A-Za-z0-9_-]{40,}/i, severity: 'high', label: 'Square OAuth secret detected' },
  { pattern: /AC[0-9a-f]{32}/, severity: 'high', label: 'Twilio Account SID detected' },
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
  // AWS CLI account/identity enumeration
  { pattern: /aws\s+sts\s+get-caller-identity/i, severity: 'high', label: 'AWS STS get-caller-identity (account enum)' },
  { pattern: /aws\s+iam\s+list-(users|roles|groups|policies|access-keys)\b/i, severity: 'high', label: 'AWS IAM enumeration' },
  { pattern: /aws\s+iam\s+create-access-key/i, severity: 'high', label: 'AWS IAM access key creation' },
  { pattern: /aws\s+iam\s+attach-(user|role|group)-policy/i, severity: 'high', label: 'AWS IAM policy attachment' },
  { pattern: /aws\s+sts\s+assume-role\b/i, severity: 'high', label: 'AWS STS assume-role (privilege escalation)' },
  { pattern: /aws\s+sts\s+assume-role-with-web-identity/i, severity: 'high', label: 'AWS STS assume-role-with-web-identity' },
  { pattern: /aws\s+organizations\s+list-(accounts|roots|policies)\b/i, severity: 'high', label: 'AWS Organizations account enumeration' },
  { pattern: /aws\s+ec2\s+describe-(instances|security-groups|vpcs|subnets)\b/i, severity: 'medium', label: 'AWS EC2 infrastructure enumeration' },
  { pattern: /aws\s+s3\s+cp\b[^\n]{0,80}(s3:\/\/|http)/i, severity: 'medium', label: 'AWS S3 copy (potential exfil)' },
  // GCP CLI abuse
  { pattern: /gcloud\s+auth\s+print-access-token/i, severity: 'high', label: 'GCP access token printed to stdout' },
  { pattern: /gcloud\s+auth\s+print-identity-token/i, severity: 'high', label: 'GCP identity token printed to stdout' },
  { pattern: /gcloud\s+iam\s+service-accounts\s+(keys\s+create|list)\b/i, severity: 'high', label: 'GCP service account key creation/list' },
  { pattern: /gcloud\s+projects\s+list\b/i, severity: 'medium', label: 'GCP project enumeration' },
  { pattern: /gcloud\s+compute\s+instances\s+list\b/i, severity: 'medium', label: 'GCP compute instance enumeration' },
  // Azure CLI abuse
  { pattern: /az\s+account\s+get-access-token/i, severity: 'high', label: 'Azure access token retrieved via az cli' },
  { pattern: /az\s+ad\s+(user|group|sp)\s+list\b/i, severity: 'high', label: 'Azure AD identity enumeration' },
  { pattern: /az\s+role\s+assignment\s+(create|list)\b/i, severity: 'high', label: 'Azure role assignment manipulation' },
  { pattern: /az\s+keyvault\s+secret\s+(show|list|download)\b/i, severity: 'high', label: 'Azure Key Vault secret access' },
  { pattern: /az\s+storage\s+(blob|account)\s+(upload|download|list)\b/i, severity: 'medium', label: 'Azure storage access (potential exfil)' },
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
  { pattern: /kubectl\s+exec\s+[^\n]*--\s*(?:bash|sh|\/bin\/sh|\/bin\/bash)\b/i, severity: 'high', label: 'kubectl exec spawning shell in pod' },
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
  { pattern: /kubectl\s+apply\s+-f\s+https?:\/\/(?!raw\.githubusercontent\.com\/kubernetes\/)/i, severity: 'medium', label: 'kubectl apply from non-official remote URL' },
  { pattern: /kubectl\s+run\s+[^\n]*--image[=\s]+[^\s]*\s+--command\s+--\s*(?:sh|bash)/i, severity: 'high', label: 'kubectl run ad-hoc pod spawning shell' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/etc[:/]/i, severity: 'high', label: 'docker run mounting host /etc directory' },
  { pattern: /docker\s+run\s+[^\n]*-v\s+\/root[:/]/i, severity: 'high', label: 'docker run mounting host /root directory' },
  { pattern: /docker\s+run\s+[^\n]*--security-opt[=\s]+seccomp[=:]unconfined/i, severity: 'high', label: 'docker run with seccomp unconfined' },
  { pattern: /docker\s+run\s+[^\n]*--security-opt[=\s]+apparmor[=:]unconfined/i, severity: 'high', label: 'docker run with AppArmor unconfined' },
  { pattern: /kubectl\s+exec\s+[^\n]*-n\s+kube-system/i, severity: 'high', label: 'kubectl exec into kube-system namespace pod' },
  { pattern: /curl\s+[^\s]*kubernetes\.default\.svc/i, severity: 'high', label: 'Accessing Kubernetes API server from inside pod' },
  { pattern: /KUBERNETES_SERVICE_HOST|KUBERNETES_PORT_443_TCP/i, severity: 'medium', label: 'Referencing Kubernetes in-cluster API env vars' },
  { pattern: /docker\s+run\s+[^\n]*--cap-add[=\s]+NET_ADMIN/i, severity: 'medium', label: 'docker run adding NET_ADMIN capability' },
  { pattern: /runc\s+--root\s+\/var\/run\/docker\/runtime/i, severity: 'high', label: 'Direct runc invocation on Docker runtime root' },
  // ── DATA EXFILTRATION ──────────────────────────────────────────────────────
  // curl posting a local file to an external host
  { pattern: /curl\s+[^|]*-d\s+@[\w.\/~-]+\s+https?:\/\/(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i, severity: 'high', label: 'curl POST file to external host' },
  // curl --data-binary @file upload
  { pattern: /curl\s+[^|]*--data-binary\s+@[\w.\/~-]+/i, severity: 'high', label: 'curl --data-binary file upload' },
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
  { pattern: /scp\s+[^|]*~\/\.(ssh|aws|env|config|gnupg|netrc)\S*\s+\w+@[\w.-]+:/i, severity: 'high', label: 'scp sensitive dotfile to remote host' },
  // scp of .env or secrets file to remote host
  { pattern: /scp\s+[^|]*\.(env|pem|key|p12|pfx)\s+\w+@[\w.-]+:/i, severity: 'high', label: 'scp secrets/cert file to remote host' },
  // rsync of sensitive dirs to remote
  { pattern: /rsync\s+[^|]*~\/\.(ssh|aws|gnupg)\s+\w+@[\w.-]+:/i, severity: 'high', label: 'rsync sensitive dotdir to remote host' },
  // tar piped to curl (archive and upload)
  { pattern: /tar\s+[czjJf]*\s*-?\s*[^|]+\|\s*curl\b/i, severity: 'high', label: 'tar archive piped to curl upload' },
  // base64 encode file then curl/wget
  { pattern: /base64\s+[^|]*\|\s*(curl|wget)\b/i, severity: 'high', label: 'base64 encoded file piped to curl/wget' },
  // base64 encode file then pipe to nc/netcat
  { pattern: /base64\s+[^|]*\|\s*nc\b/i, severity: 'high', label: 'base64 encoded file piped to netcat' },
  // nc / netcat file transfer outbound with explicit remote host
  { pattern: /nc\s+[^|]*-[we]\s+\d+\s+<\s*[\w.\/~-]+/i, severity: 'high', label: 'netcat file transfer to remote host' },
  // nc pipe outbound to remote (not localhost)
  { pattern: /\|\s*nc\s+(?!localhost|127\.0\.0\.1)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/i, severity: 'high', label: 'pipe data to netcat remote IP' },
  // uploading ~/.ssh directory/keys
  { pattern: /curl\s+[^|]*(--data|--upload-file|-T)\s+[^|]*~\/\.ssh\//i, severity: 'high', label: 'curl upload of ~/.ssh content' },
  // uploading .env file externally
  { pattern: /curl\s+[^|]*(--data|--upload-file|-T|-d)\s+[^|]*\.env\b/i, severity: 'high', label: 'curl exfil of .env file' },
  // Telegram bot webhook used for exfil
  { pattern: /curl\s+[^|]*https?:\/\/api\.telegram\.org\/bot[\w:]+\/sendMessage/i, severity: 'high', label: 'Telegram bot API used for data exfil' },
  // Discord webhook POST
  { pattern: /curl\s+[^|]*https?:\/\/discord(app)?\.com\/api\/webhooks\//i, severity: 'high', label: 'Discord webhook exfiltration' },
  // Slack webhook POST with data
  { pattern: /curl\s+[^|]*-d\s+[^|]*https?:\/\/hooks\.slack\.com\/services\//i, severity: 'high', label: 'Slack webhook used for data exfil' },
  // wget to upload file to external
  { pattern: /wget\s+[^|]*--post-file=[\w.\/~-]+\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i, severity: 'high', label: 'wget --post-file exfiltration' },
  // python requests/urllib POST of file content to external
  { pattern: /requests\.(post|put)\s*\([^)]*open\s*\([^)]*\.(env|pem|key|ssh)/i, severity: 'high', label: 'Python requests POST of sensitive file' },
  // exfil via /dev/tcp bash redirection to remote
  { pattern: /\/dev\/tcp\/(?!localhost|127\.0\.0\.1)[\w.-]+\/\d{2,5}/i, severity: 'high', label: 'bash /dev/tcp outbound connection for exfil' },
  // sftp put of sensitive file to remote
  { pattern: /sftp\s+[^|]*put\s+[^|]*\.(env|pem|key|ssh|p12)\b/i, severity: 'high', label: 'sftp PUT of secrets/cert file' },
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
  { pattern: /<system>/i, severity: 'medium', label: 'instruction smuggling via <system> tag' },
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
  { pattern: /crontab\s+-[^l]/i, severity: 'high', label: 'crontab modification (non-list)' },
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
  { pattern: /\bmodprobe\s+(?!--remove|--show|-r\b)\S+/i, severity: 'medium', label: 'suspicious kernel module load via modprobe' },
  { pattern: /echo\s+.+>>\s*~?\/\.bashrc\b/i, severity: 'high', label: '.bashrc backdoor append' },
  { pattern: /echo\s+.+>>\s*~?\/\.bash_profile\b/i, severity: 'high', label: '.bash_profile backdoor append' },
  { pattern: /echo\s+.+>>\s*~?\/\.profile\b/i, severity: 'high', label: '.profile backdoor append' },
  { pattern: /launchctl\s+load\s+\S+\.plist/i, severity: 'high', label: 'launchd plist loaded for persistence (macOS)' },
  { pattern: /cp\s+\S+\s+~?\/Library\/LaunchAgents\//i, severity: 'high', label: 'LaunchAgent plist dropped (macOS persistence)' },
  { pattern: /cp\s+\S+\s+\/Library\/LaunchDaemons\//i, severity: 'high', label: 'LaunchDaemon plist dropped (macOS persistence)' },
  { pattern: /echo\s+.+>>\s*\/etc\/ld\.so\.preload/i, severity: 'high', label: '/etc/ld.so.preload backdoor append' },
  { pattern: /chmod\s+4[0-9]{3}\s+\S+/i, severity: 'high', label: 'setuid octal chmod (e.g., 4755)' },
  { pattern: /\/etc\/init\.d\/\S+\s+(enable|start)|update-rc\.d\s+\S+\s+enable/i, severity: 'medium', label: 'SysV init service persistence' },
  { pattern: /at\s+now\s+<<\s*EOF/i, severity: 'medium', label: 'at-job scheduled command (persistence)' },
  { pattern: /echo\s+.+>>\s*~?\/\.zshrc\b/i, severity: 'high', label: '.zshrc backdoor append' },
  { pattern: /\bptrace\b.*PTRACE_ATTACH/i, severity: 'high', label: 'ptrace ATTACH (process injection)' },
  { pattern: /\/proc\/[0-9]+\/mem\b/i, severity: 'high', label: 'direct /proc/PID/mem access (process memory write)' },
  { pattern: /echo\s+.+>>\s*\/root\/\.ssh\/authorized_keys/i, severity: 'high', label: 'root SSH authorized_keys append' },
];
