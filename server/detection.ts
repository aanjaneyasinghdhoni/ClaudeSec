// server/detection.ts
//
// Side-effect-free module that exports the built-in threat-detection rules.
// Importing this module has no observable side effects (no DB, no fs writes,
// no server setup) so scripts and tests can import it cheaply without pulling
// in the Express server.
//
// Two exports:
//   CORE_SEVERITY_RULES  — the ~194 hand-authored core rule literals (no EXTRA spread).
//                          Used by tests/ruleSelfTest.ts to dedup EXTRA rules against
//                          core built-ins only.
//   SEVERITY_RULES       — combined array (core + EXTRA), length ~673.
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

  // Destructive filesystem operations.
  // The two deletion rules below only fire when the target is the WHOLE root or
  // the WHOLE home — the target must end at end-of-line, whitespace, a glob or a
  // shell separator, so every sub-path (`rm -rf /tmp/build-cache`,
  // `rm -rf ~/project/node_modules`, `rm -rf /var/folders/…`) stays clean. The
  // flag span is order- and spelling-independent (`-rf`, `-fr`, `-r -f`, `-rfv`,
  // `--recursive --force`, the POSIX `--` separator) and bounded to five tokens so
  // it stays linear; an optional quote pair on either side catches `rm -rf "/"`.
  { pattern: /\brm\s+(?:-[-a-zA-Z]+\s+){1,5}['"]?\/['"]?\s*(?:$|[\s*;&|>])/m,  severity: 'high', label: 'Recursive root deletion' },
  { pattern: /\brm\s+(?:-[-a-zA-Z]+\s+){1,5}['"]?(?:~|\$\{?HOME\}?)\/?['"]?\s*(?:$|[\s*;&|>])/m, severity: 'high', label: 'Home directory deletion' },
  { pattern: /rm\s+-rf\s+\.\s*$/i,                          severity: 'high', label: 'Current directory wipe' },
  { pattern: /mkfs\./i,                                     severity: 'high', label: 'Filesystem format command' },
  { pattern: /dd\s+if=.*of=\/dev\//i,                       severity: 'high', label: 'Raw disk write via dd' },
  { pattern: /shred\s+/i,                                   severity: 'high', label: 'Secure file destruction' },
  // Whole-device targets only. `of=` / the redirect target must name a real block
  // device (sda, nvme0, disk2, hda, vda, mmcblk0) — writing an image file
  // (`dd if=/dev/zero of=./disk.img`) or the null sink (`… > /dev/null`) is
  // everyday tooling and must stay silent. `of=` alone is not enough: the source
  // side (`if=/dev/zero`) is harmless, the destination side is what destroys.
  { pattern: /\bdd\b[^\n]{0,200}\bof=['"]?\/dev\/(?:sd[a-z]|nvme\d|r?disk\d|hd[a-z]|vd[a-z]|mmcblk\d)/i, severity: 'high', label: 'Disk device wipe via dd' },
  { pattern: />\s*['"]?\/dev\/(?:sd[a-z]|nvme\d|r?disk\d|hd[a-z]|vd[a-z]|mmcblk\d)/i, severity: 'high', label: 'Raw disk overwrite via redirect' },
  // Deleting from the filesystem root or the home tree via find — the same intent
  // as `rm -rf /`, expressed with a traversal instead. A relative start path
  // (`find . -name "*.pyc" -delete`) is routine cleanup and is not matched.
  { pattern: /find\s+['"]?(?:\/|~|\$\{?HOME\}?)['"]?\s+[^\n]{0,120}-(?:delete\b|exec\s+(?:\/bin\/)?(?:rm|shred|unlink)\b)/i, severity: 'high', label: 'Find-based root deletion' },

  // Remote code execution.
  // The pipe target must be a shell as a WHOLE word — `| shasum -a 256` and
  // `| shellcheck` are ordinary verification steps and must not fire. The shell
  // alternation covers the interpreters an evasive one-liner actually reaches for
  // (sh/bash/zsh/ksh/dash), optionally behind `sudo`.
  { pattern: /curl\s+[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i, severity: 'high', label: 'Remote code execution via curl' },
  { pattern: /wget\s+[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b/i, severity: 'high', label: 'Remote code execution via wget' },
  // What makes `curl … | python` remote code execution is that the downloaded
  // bytes ARE the program: a bare interpreter takes its script from stdin. Give
  // the interpreter its own program and the roles invert — the code is the
  // locally-authored one on the command line and the download is only its INPUT.
  // `curl … | python3 -c "import sys,json; d=json.load(sys.stdin); print(…)"` is
  // how an agent reads a JSON API from a shell, and it was the largest single
  // source of would-be denials in local history: 77 matches in 76 days, not one
  // of them executing anything remote.
  //
  // But "has -c" is not the same as "is safe", so the stand-down is decided on
  // what the inline program DOES, not on the flag's presence:
  //   • `-m <module>` stands down only for the data modules (`json.tool`,
  //     `base64`, `csv`, …). A module never runs stdin as code, but the general
  //     `-m` is a wide door — `-m pip install -r /dev/stdin` installs whatever
  //     was downloaded — so the carve-out is an allowlist, not a wildcard.
  //   • `-c` stands down only when the program contains no way to execute or
  //     deserialise what it reads. `-c "import sys; exec(sys.stdin.read())"` and
  //     the pickle equivalent are genuine remote execution wearing the shape of
  //     the benign form, and they still fire.
  // Both scans stop at the next pipeline or command separator, so the flags of
  // one command cannot excuse a different one: in `curl … | python && python3 -c
  // "…"` the first pipe is still judged on its own, bare, terms.
  { pattern: /curl\s+[^\n]*\|\s*python\d*(?:\.\d+)?\b(?![^\n|;&]{0,120}\s-{1,2}m\s*(?:json(?:\.tool)?|base64|csv|gzip|bz2|lzma|zipfile|tarfile|hashlib|pprint|tomllib|calendar)\b)(?![^\n|;&]{0,120}\s-{1,2}c\b(?![^\n]{0,240}(?:\bexec\b|\beval\b|\bcompile\b|__import__|os\.system|os\.popen|subprocess|runpy|importlib|pickle|marshal|pty\.spawn)))/i, severity: 'high', label: 'Remote Python execution via curl' },
  { pattern: /wget\s+[^\n]*\|\s*python\d*(?:\.\d+)?\b(?![^\n|;&]{0,120}\s-{1,2}m\s*(?:json(?:\.tool)?|base64|csv|gzip|bz2|lzma|zipfile|tarfile|hashlib|pprint|tomllib|calendar)\b)(?![^\n|;&]{0,120}\s-{1,2}c\b(?![^\n]{0,240}(?:\bexec\b|\beval\b|\bcompile\b|__import__|os\.system|os\.popen|subprocess|runpy|importlib|pickle|marshal|pty\.spawn)))/i, severity: 'high', label: 'Remote Python execution via wget' },
  { pattern: /curl\s+.*\|\s*perl/i,                         severity: 'high', label: 'Remote Perl execution via curl' },
  { pattern: /curl\s+-o\s+.*&&\s*(ba)?sh/i,                 severity: 'high', label: 'Download-and-execute pattern' },
  { pattern: /git\s+clone\s+.*&&\s*(ba)?sh/i,               severity: 'high', label: 'Clone-and-execute' },

  // Credential-named environment variable sent in a request BODY. The body is
  // what separates exfiltration from ordinary API use: passing a token via
  // `-H "Authorization: Bearer $GITHUB_TOKEN"` is how every client authenticates
  // and must stay silent, while POSTing that same value as form/data content is
  // not something a legitimate client does. The variable name must itself look
  // like a credential, so `-d "$PAYLOAD"` does not trip it.
  { pattern: /\b(?:curl|wget)\b[^\n]{0,200}?(?:\s-d\b|--data(?:-raw|-binary|-urlencode)?\b|\s-F\b|--form\b)\s*['"]?[^\n'"]{0,80}\$\{?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*\}?/i, severity: 'critical', label: 'Environment credential sent in request body' },
  // Two-step form of the same intent: save the remote body to disk (`-o`, `-O`,
  // `--output`, or a redirect), then hand it to a shell on the next command in the
  // chain. Splitting the download from the execution defeats the single-pipe rules
  // above, so the chain separator is matched explicitly.
  { pattern: /\b(?:curl|wget)\b[^\n]{0,200}(?:\s-[oO]\b|--output\b|>)\s*['"]?[^\s'"]{1,80}[^\n]{0,60}(?:&&|;|\|\|)\s*(?:sudo\s+)?(?:(?:ba|da|k|z)?sh|source)\s+\S/i, severity: 'high', label: 'Download-then-execute chain' },

  // Code injection.
  // `eval` / `exec` / `Function` must be the START of an identifier, not the tail
  // of one: `re.exec(line)`, `enforceEval(text)` and `registerFunction("x")` are
  // ordinary code and used to fire on every source file we touched. A leading `.`
  // is excluded too, so a method call on some other object is not a bare eval.
  // The Function rule stays case-SENSITIVE — the constructor is capitalised, and
  // lower-casing it swept up every `function(` in the corpus.
  // A bare `eval(` is an alert, not a block. This pattern reads any text blob —
  // including commit messages and code comments — so `git commit -m "fix: handle
  // eval() in parser"` used to rate high and, in enforce mode, be refused. The
  // fourteen anchored eval rules in severityRulesExtra.ts carry the real signal:
  // they require the decode or the fetch beside it (`eval(atob(`, `eval(Buffer
  // .from(…,'base64'))`, fetch-then-eval, char-code obfuscation, the ruby/perl/node
  // decode one-liners) and all stay high. A genuine injection essentially always
  // pairs eval with one of those, so the unanchored form is the noisy half.
  { pattern: /(^|[^\w.$])eval\s*\(/i,                       severity: 'medium', label: 'Code eval injection' },
  // Same reasoning as the eval rule above, and the same evidence: an unanchored
  // `exec(` over a raw text blob matches prose, code comments and commit messages,
  // and at high severity that refused them outright. The forms that actually spawn
  // a process are each anchored elsewhere and stay high — `child_process.exec`,
  // `subprocess.call`, `os.system`, `os.popen` and `Runtime.getRuntime().exec()`
  // below, plus the encoded variants in severityRulesExtra.ts (`exec(base64
  // .b64decode(`, `exec(compile(base64`, zlib/gzip-decompress-then-exec, the hex-
  // escape feed, `php -r "…exec('/bin/sh')"`). What this rule uniquely still sees
  // is a bare `exec(` in a language none of those name — real, but narrow, and it
  // keeps alerting at medium.
  { pattern: /(^|[^\w.$])exec\s*\(/i,                       severity: 'medium', label: 'Exec injection' },
  { pattern: /(^|[^\w$.])(new\s+)?Function\s*\(\s*["'`]/,   severity: 'high', label: 'Dynamic function constructor' },
  // The shell-invoking members only. `execFile` takes an argv array and spawns no
  // shell, so it is the SAFE call this project recommends — it must not fire.
  { pattern: /child_process\.exec(?:Sync)?\s*\(/i,          severity: 'high', label: 'Node.js child process exec' },
  { pattern: /subprocess\.call\s*\(/i,                      severity: 'high', label: 'Python subprocess execution' },
  { pattern: /os\.system\s*\(/i,                            severity: 'high', label: 'Python os.system execution' },
  { pattern: /os\.popen\s*\(/i,                             severity: 'high', label: 'Python os.popen execution' },
  { pattern: /Runtime\.getRuntime\(\)\.exec/i,              severity: 'high', label: 'Java runtime exec' },

  // SQL destruction.
  // Split the same way `eval(` / `exec(` are split just above, and for the same
  // reason: the matchers below read any text blob, and destructive SQL keywords
  // spend most of their life as TEXT rather than as a statement. Of fifty
  // would-be denials in local history, all but a handful were `grep -i "drop
  // table" migrations/*.sql`, a commit message describing a migration, or a
  // guard script's own fixture — refusing those refuses reading and reviewing
  // schema work, which is most of what schema work is.
  //
  // So the act blocks and the mention alerts. This first rule is the act in its
  // commonest shape: a database client and its destructive statement on ONE
  // line (`psql … -c "DROP TABLE …"`, `sqlite3 db "TRUNCATE …"`). It cannot see
  // the other two shapes, because `[^\n]` stops at the end of the line and the
  // client is not always on the left:
  //   • the statement arrives on stdin  — `echo "DROP TABLE x;" | psql …`
  //   • the statement arrives by heredoc — `psql … <<'SQL'` then the body
  // Those are severityRulesExtra.ts's `SQL destructive statement piped into a
  // database client` and `… fed to a database client by heredoc`. All three
  // carry the same tier because they are the same act; only the plumbing differs.
  //
  // Four boundary conditions, each paid for by a real false denial:
  //   • The left boundary is `[^\w|-]`, not `\b`. `-` keeps the `sqlite3` inside
  //     `better-sqlite3` — a dependency name, not an invocation — from
  //     qualifying; `|` keeps a client NAMED INSIDE a grep alternation
  //     (`grep -E "…|psql|drop table…"`) from qualifying, which is a search, not
  //     a session. A real shell pipe puts a space before the client, so
  //     `… | psql` is unaffected.
  //   • `TRUNCATE` is also the name of a Postgres PRIVILEGE, so `GRANT TRUNCATE
  //     ON …` and `REVOKE TRUNCATE ON …` — routine, and the opposite of
  //     destructive — must not be read as the statement. The target cannot be
  //     `ON` or `FROM`.
  //   • The statement may not be preceded by `%`. `'%DROP TABLE%'` is a LIKE
  //     pattern; the one place it shows up is a read-only query COUNTING
  //     destructive commands, which is the purest mention there is.
  //   • `supabase db` and `prisma db` are not in the client list. Neither takes
  //     a raw SQL statement as an argument, so the token can only ever
  //     co-occur with a mention — and it did, matching a design note that
  //     quoted `supabase db diff` output 287 characters above a DDL example.
  //
  // DELETE and DROP COLUMN join DROP and TRUNCATE here, but only in the shape
  // that destroys everything. `DELETE FROM t;` with no WHERE is a table wipe;
  // `DELETE FROM t WHERE id = …` is how test rows get cleaned up, and it is 48
  // of the 64 client-side deletes in local history. Scoping a delete is the
  // operator saying which rows they meant, so a scoped delete never blocks.
  { pattern: /(?:^|[^\w|-])(?:psql|mysql|mariadb|sqlite3|mongosh|clickhouse-client|cockroach|sqlcmd|pgcli|mycli)\b[^\n]{0,400}(?:^|[^\w\n%])(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|KEYSPACE)\b|TRUNCATE\s+(?:TABLE\s+)?(?!ON\b|FROM\b)\w|ALTER\s+TABLE\s+[^;\n]{1,120}\bDROP\s+COLUMN\b|DELETE\s+FROM\s+[\w."\[\]`]{1,80}\s*;|DELETE\s+FROM\s+[\w.\[\]`]{1,80}\s*["'](?:\s|[;&|)]|$))/i, severity: 'high', label: 'SQL destructive statement executed through a database client' },
  // …and these are the mention: still detected, still on the record, but at the
  // alert tier, because a keyword in a search pattern is not a dropped table.
  { pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)/i,             severity: 'medium', label: 'SQL destructive operation' },
  { pattern: /TRUNCATE\s+TABLE/i,                           severity: 'medium', label: 'SQL table truncation' },
  { pattern: /DELETE\s+FROM\s+\w+\s*;/i,                    severity: 'medium', label: 'SQL unrestricted DELETE' },
  { pattern: /ALTER\s+TABLE\s+.*DROP\s+COLUMN/i,            severity: 'medium', label: 'SQL column drop' },

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
  // A comment only counts as an injection when it carries a real override verb
  // AND its object — tool pragmas like `<!-- prettier-ignore -->` say "ignore"
  // but instruct a formatter, not the model.
  { pattern: /<!--[^>]{0,200}\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\b/i, severity: 'high', label: 'Prompt injection: HTML comment directive' },
  { pattern: /translate.*into.*instructions/i,                   severity: 'high', label: 'Prompt injection: translation attack' },
  { pattern: /repeat\s+after\s+me\s*:/i,                         severity: 'high', label: 'Prompt injection: echo attack' },

  // Credential / secret patterns
  { pattern: /AKIA[0-9A-Z]{16}/,                                severity: 'high', label: 'AWS access key detected' },
  { pattern: /ASIA[0-9A-Z]{16}/,                                severity: 'high', label: 'AWS temporary key detected' },
  { pattern: /aws_secret_access_key\s*[=:]\s*\S{30,}/i,         severity: 'high', label: 'AWS secret key in plaintext' },
  { pattern: /ghp_[A-Za-z0-9]{36}/,                             severity: 'high', label: 'GitHub PAT detected' },
  { pattern: /gho_[A-Za-z0-9]{36}/,                             severity: 'high', label: 'GitHub OAuth token detected' },
  { pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,      severity: 'high', label: 'GitHub fine-grained PAT detected' },
  // `sk-` must start the token, not sit inside one: ordinary identifiers such as
  // `task-7f3a9b2c…` and `risk-…` contain the same three characters.
  { pattern: /(^|[^A-Za-z0-9_-])sk-[A-Za-z0-9]{20,}/,           severity: 'high', label: 'API secret key detected (OpenAI/Stripe)' },
  { pattern: /sk-ant-[A-Za-z0-9-]{90,}/,                        severity: 'high', label: 'Anthropic API key detected' },
  { pattern: /AIza[0-9A-Za-z\\-_]{35}/,                         severity: 'high', label: 'Google API key detected' },
  { pattern: /xox[bpsa]-[A-Za-z0-9-]{10,}/,                     severity: 'high', label: 'Slack token detected' },
  { pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----/i, severity: 'high', label: 'Private key in plaintext' },
  // A certificate is the PUBLIC half of a key pair — it is published to every
  // client that connects. Worth an audit trail, never a high-severity finding.
  { pattern: /-----BEGIN\s+CERTIFICATE-----/i,                  severity: 'low',  label: 'TLS certificate in plaintext' },
  { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high', label: 'JWT token detected' },
  { pattern: /password\s*[=:]\s*["'][^"']{4,}/i,                severity: 'high', label: 'Hardcoded password detected' },
  // A database URL carries a password in the clear, so it is a credential
  // wherever it appears — EXCEPT when the host it points at is this machine.
  // A loopback DSN is a local development stack: `supabase start`, `docker
  // compose up`, a test container. Its password is the framework's own published
  // default, it protects nothing, and it cannot travel — there is no remote
  // service on the other end to be compromised. Local history is unambiguous on
  // the cost of ignoring that: 318 of 698 would-be denials in 76 days, 45.6% of
  // the entire enforcement surface, were `psql "postgresql://…@127.0.0.1:54322/
  // postgres"` against a local Supabase instance. Every non-loopback host — a
  // managed Postgres endpoint, an RDS instance, a staging box — still fires,
  // and that population is two commands in the same 76 days, which is what a
  // rule that refuses a command should look like.
  // The loopback carve-out is spelled out on each of the four rules rather than
  // shared, because these literals are what scripts/build-enforcement-rules.ts
  // serialises into the hook snapshot: a rule's `source` has to be the whole
  // pattern, not a reference to one.
  { pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@(?!(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[?::1\]?|host\.docker\.internal)(?:[:/?#]|$))/i, severity: 'high', label: 'MongoDB connection string with credentials' },
  { pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@(?!(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[?::1\]?|host\.docker\.internal)(?:[:/?#]|$))/i, severity: 'high', label: 'PostgreSQL connection string with credentials' },
  { pattern: /mysql:\/\/[^:]+:[^@]+@(?!(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[?::1\]?|host\.docker\.internal)(?:[:/?#]|$))/i, severity: 'high', label: 'MySQL connection string with credentials' },
  { pattern: /redis:\/\/[^:]*:[^@]+@(?!(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[?::1\]?|host\.docker\.internal)(?:[:/?#]|$))/i, severity: 'high', label: 'Redis connection string with credentials' },

  // Supply-chain attacks.
  // Redirecting a package manager at a NON-official index is the attack; pointing
  // it at the project's own documented index is not. PyTorch publishes its CPU/CUDA
  // wheels on download.pytorch.org and the install line is copied straight out of
  // their docs, so the well-known official hosts are carved out — anything else
  // still fires. Same idea for npm: the default registry is not an override.
  { pattern: /pip\s+install\s+[^\n]*--index-url[=\s]+["']?(?!https?:\/\/(?:pypi\.org|files\.pythonhosted\.org|download\.pytorch\.org)(?:[\/:\s'"]|$))/i, severity: 'high', label: 'Supply-chain: custom PyPI index' },
  { pattern: /pip\s+install\s+.*--extra-index-url/i,            severity: 'high', label: 'Supply-chain: extra PyPI index' },
  // The left boundary keeps `pnpm install …` (and any other `…npm` wrapper) out.
  { pattern: /(^|[^\w-])npm\s+install[^\n]*--registry/i,        severity: 'high', label: 'Supply-chain: custom npm registry' },
  { pattern: /(^|[^\w-])npm\s+config\s+set\s+registry(?!\s*=?\s*["']?https?:\/\/registry\.npmjs\.org)/i, severity: 'high', label: 'Supply-chain: npm registry override' },
  { pattern: /gem\s+install.*--source/i,                         severity: 'high', label: 'Supply-chain: custom gem source' },
  { pattern: /pip\s+install\s+--pre\s/i,                         severity: 'high', label: 'Supply-chain: pre-release package install' },

  // Reverse shells & backdoors
  { pattern: /\/dev\/tcp\//i,                                    severity: 'high', label: 'Bash TCP reverse shell' },
  { pattern: /nc\s+-[elp]+.*\d{2,5}/i,                          severity: 'high', label: 'Netcat listener/reverse shell' },
  { pattern: /ncat\s+-[elp]+/i,                                 severity: 'high', label: 'Ncat reverse shell' },
  // Match the actual call shape (`socket.socket(…)` … `.connect(`), not three
  // loose keywords on one line — the old form fired on any Python command that
  // merely mentioned sockets.
  { pattern: /socket\.socket\([^\n]{0,120}\.connect\(/i,         severity: 'high', label: 'Python socket reverse shell' },
  { pattern: /perl.*socket.*INET/i,                              severity: 'high', label: 'Perl socket reverse shell' },
  { pattern: /ruby.*TCPSocket/i,                                 severity: 'high', label: 'Ruby reverse shell' },
  { pattern: /php.*fsockopen/i,                                  severity: 'high', label: 'PHP reverse shell' },
  { pattern: /socat\s+.*EXEC/i,                                 severity: 'high', label: 'Socat exec shell' },
  { pattern: /mknod.*\/tmp\/.*p.*sh/i,                           severity: 'high', label: 'Named pipe shell' },
  // A remote (-R) or dynamic (-D) forward turns an outbound SSH session into an
  // inbound channel — the quiet twin of a reverse shell. A plain `-L` local
  // forward (`ssh -L 5432:localhost:5432 db@host`) is everyday tunnelling and is
  // not matched; the flag must be followed by a real `[bind:]port:` spec.
  { pattern: /\bssh\b[^\n]{0,80}\s-[a-zA-Z]*[RD]\s*(?:[\w.*]{0,15}:)?\d{1,5}:/i, severity: 'high', label: 'SSH reverse/dynamic port forward' },

  // Persistence / privilege escalation.
  // Listing the crontab reads it; editing or installing one changes what runs
  // unattended. Those are different acts and get different severities.
  { pattern: /(^|[^\w-])crontab\s+-l\b/i,                        severity: 'low',  label: 'Crontab listing' },
  { pattern: /crontab\s+(?:-e\b|[^-\s]\S{0,80})/i,               severity: 'high', label: 'Crontab modification' },
  { pattern: /\/etc\/cron\./i,                                   severity: 'high', label: 'System cron directory access' },
  // Enabling or starting an existing unit is routine administration. What makes
  // systemd a persistence vector is DROPPING a new unit file, which
  // severityRulesExtra.ts already rates high; this stays low so ordinary service
  // management does not crowd out that signal.
  { pattern: /systemctl\s+(enable|start|daemon-reload)/i,        severity: 'low',  label: 'Systemd service manipulation' },
  { pattern: /launchctl\s+(load|submit)/i,                       severity: 'high', label: 'macOS LaunchAgent manipulation' },
  // Persistence on macOS is INSTALLING a LaunchAgent, not looking at one. The
  // bare directory substring made no such distinction, so `cat ~/Library/
  // LaunchAgents/com.example.agent.plist` and `ls ~/Library/LaunchAgents/` —
  // 22 of the 23 matches in local history, every one of them someone checking
  // whether their own service was installed — carried the blocking tier. The
  // first rule now needs a verb that puts a file there or loads one; the second
  // keeps the read on the record at the audit tier, where recon belongs.
  // `PlistBuddy` appears on both sides of that line, so it qualifies only with a
  // mutating subcommand: `-c "Print"` reads, `-c "Add …"` rewrites.
  { pattern: /(?:>>?\s*['"]?[^\s'";&|]{0,80}|\b(?:cp|mv|tee|install|ln|ditto|rsync|unzip|curl|wget|plutil)\b[^\n;&|]{0,120}|\blaunchctl\s+(?:load|bootstrap|enable|submit)\b[^\n;&|]{0,120}|\bPlistBuddy\b[^\n;&|]{0,40}-c\s+['"]?(?:Add|Set|Delete|Merge|Import)\b[^\n;&|]{0,120})\/Library\/LaunchAgents\//i, severity: 'high', label: 'macOS LaunchAgent installed or loaded (persistence)' },
  { pattern: /\/Library\/LaunchAgents\//i,                       severity: 'low',  label: 'macOS LaunchAgent directory access' },
  { pattern: /visudo/i,                                          severity: 'high', label: 'Sudoers file modification' },
  { pattern: /usermod\s+.*-aG\s+(sudo|wheel|root)/i,            severity: 'high', label: 'Privilege escalation via group add' },
  { pattern: /chown\s+root/i,                                   severity: 'high', label: 'Ownership change to root' },
  // Only the four-digit modes that actually carry a setuid/setgid/sticky bit, or
  // the symbolic `+s`. The old three-digit form matched `chmod 644 README.md` and
  // `chmod 600 ~/.ssh/id_ed25519` — the two most common permission commands there
  // are, neither of which touches a special bit.
  { pattern: /\bset[ug]id\b|chmod\s+(?:[2467][0-7]{3}|[ug]?\+s)\b/i, severity: 'high', label: 'SUID/SGID bit manipulation' },
  // The symbolic spelling with flags in front (`chmod -R a+s dir`) — a classic
  // persistence backdoor. `chmod +x` must stay silent, so the mode is required to
  // end in `s`, never merely to start with `+`.
  { pattern: /\bchmod\s+(?:-[a-zA-Z]{1,8}\s+){0,3}[ugoa]{0,3}\+s\b/i, severity: 'high', label: 'SUID bit set via chmod' },

  // Container escape
  { pattern: /docker\.sock/i,                                    severity: 'high', label: 'Docker socket access' },
  { pattern: /--privileged/i,                                    severity: 'high', label: 'Privileged container execution' },
  { pattern: /mount\s+.*\/host/i,                                severity: 'high', label: 'Host filesystem mount' },
  { pattern: /nsenter\s+/i,                                      severity: 'high', label: 'Namespace enter (container escape)' },
  // Read-only capability introspection — recon, not an escape. Audit trail only.
  { pattern: /capsh\s+--print/i,                                 severity: 'low',  label: 'Container capabilities check' },

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
  // The gap between the verb and the path cannot step OVER a dotenv token, so the
  // rule always judges the FIRST dotenv on the line. Without that, `cp .env.example
  // .env.local` skipped past the excused template and matched the second argument.
  // The gap also cannot step over a shell separator. A forty-character window is
  // wide enough to cross `; ` or `| ` into a completely different command, and in
  // local history that is exactly what it did: `… | head -20; echo "---"; ls -la
  // .env` paired the `head` of one command with the `.env` of another and refused
  // a directory listing. The verb and its argument have to belong to the same
  // command for the match to mean anything.
  // `source` was removed from the verb list and given its own rule below: it
  // loads the variables into a process environment rather than printing them into
  // the transcript, which is a different act with a different exposure.
  { pattern: /(cat|less|more|head|tail|cp|base64|xxd)\b(?:(?!\.env)[^\n>;|&`]){0,40}(^|\/|\s)\.env\b(?!\.?(?:example|sample|template|dist|tpl)(?:[\s'";|&)]|$))(\.[a-z]+)?\b/i, severity: 'high', label: 'Dotenv file read' },

  // ═══════════════════════════════════════════════════════════════════════════
  // MEDIUM — exfiltration, sensitive access, recon, suspicious patterns
  // ═══════════════════════════════════════════════════════════════════════════

  // Environment & config access
  { pattern: /process\.env/i,                                    severity: 'medium', label: 'Environment variable access' },
  // `.env` must be its own path token. Unanchored, this matched the `.env` inside
  // every `process.env.FOO` and `import.meta.env` in the codebase. The committed,
  // secret-free templates are excluded on the same terms as the high-severity
  // `Dotenv file read` rule and the enforce floor — a template is only excused
  // when the keyword is the FINAL path token, so `.env.example.bak` still counts.
  { pattern: /(^|[\s"'`=:,(\[\/])\.env\b(?!\.?(?:example|sample|template|dist|tpl)(?:[\s'";|&)]|$))/, severity: 'medium', label: 'Dotenv file access' },
  // `source .env.live` / `set -a; . ./.env; set +a` is how a shell loads a
  // project's configuration before running it, and it was the largest single
  // group inside the old high-severity read rule — enough that enforce mode
  // would have refused starting the maintainer's own containers. Sourcing does
  // not disclose the values the way `cat` does: they land in a process
  // environment, not in the agent's transcript. It is still worth an alert,
  // because everything downstream of it inherits those secrets, and the
  // exfiltration floor is what catches them leaving. Templates are excused on
  // exactly the same terms as the two rules above.
  { pattern: /(?:^|[\n;&|(]\s*|\s)(?:source|\.)\s+['"]?(?:[^\s'";|&]{0,60}\/)?\.env\b(?!\.?(?:example|sample|template|dist|tpl)(?:[\s'";|&)]|$))(\.[a-z]+)?\b/i, severity: 'medium', label: 'Dotenv file sourced into the shell environment' },
  { pattern: /cat\s+\/etc\/passwd/i,                             severity: 'medium', label: 'Passwd file read' },
  { pattern: /\/etc\/(shadow|hosts|sudoers|resolv\.conf)/i,      severity: 'medium', label: 'Sensitive system file access' },
  { pattern: /\/etc\/ssl\/private/i,                             severity: 'medium', label: 'SSL private key directory' },
  // A bare `env` at command position dumps the environment; the same three letters
  // at the end of an assignment (`NODE_ENV=production …`) do not.
  { pattern: /\bprintenv\b|(?:^|[;&|]\s*)env\s*$/i,              severity: 'medium', label: 'Environment dump' },

  // SSH & key access
  { pattern: /ssh-add/i,                                         severity: 'medium', label: 'SSH key manipulation' },
  // Private-key access must be tested BEFORE the generic directory rule below:
  // matching is first-wins, so a broad `~/.ssh/` rule placed first would swallow
  // this and rate a real key read at the directory tier. `.pub` is excluded —
  // publishing a public key is how authorized_keys gets populated.
  // A read/copy verb is required: `chmod 600 ~/.ssh/id_ed25519` is the
  // recommended hardening step, not an exposure, and naming the file alone is
  // not access.
  { pattern: /\b(?:cat|less|more|head|tail|cp|scp|rsync|base64|xxd|openssl|source|curl|wget|nc)\b[^\n]{0,60}~\/\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)(?!\.pub)/i, severity: 'high', label: 'SSH private key access' },
  // Merely touching ~/.ssh is an audit-trail signal, not a compromise: the two
  // most common forms are `chmod 600` on a key (the recommended hardening) and
  // copying a `.pub` into authorized_keys. Real key exposure is caught above, so
  // this stays low rather than crowding out the high tier.
  { pattern: /~\/\.ssh\//i,                                      severity: 'low',  label: 'SSH directory access' },
  // Creating a NEW key pair exposes no existing secret — it is setup, not access.
  { pattern: /ssh-keygen/i,                                      severity: 'low',    label: 'SSH key generation' },
  { pattern: /authorized_keys/i,                                 severity: 'medium', label: 'SSH authorized_keys access' },
  // The catch-all for a private key living OUTSIDE `~/.ssh` (a deploy key checked
  // into `/opt/keys`, a CI runner's `./id_rsa`). It follows the same verb+target
  // shape as the `.aws/credentials`, `~/.ssh/id_*` and dotenv rules above, because
  // the bare-filename form it replaced fired on the entire public-key workflow:
  // `chmod 600 ~/.ssh/id_ed25519` (the recommended hardening), `ssh-add`,
  // `ssh-keygen -f`, `ssh-copy-id …id_ed25519.pub`, even `git config
  // user.signingkey …pub`. High rules bake to `action: block`, so every one of
  // those was refused outright in enforce mode. Naming a key is not reading it —
  // `~/.ssh/` still leaves a low audit trail, `ssh-add` a medium one, and a real
  // read through any of these verbs still rates high. `.pub` is excluded: the
  // public half is the thing you are meant to publish.
  { pattern: /\b(?:cat|less|more|head|tail|cp|mv|scp|sftp|rsync|base64|xxd|strings|openssl|source|curl|wget|nc|netcat|tar|zip|gpg|python\d?|node|ruby|perl|awk|sed|dd)\b[^\n]{0,80}?id_(?:rsa|ed25519|ecdsa|dsa)\b(?!\.pub)/i, severity: 'high', label: 'SSH private key file access' },

  // Encoding / obfuscation
  { pattern: /atob\s*\(/i,                                       severity: 'medium', label: 'Base64 decode (JS)' },
  { pattern: /base64\s+-d/i,                                     severity: 'medium', label: 'Base64 decode (CLI)' },
  { pattern: /base64\.b64decode/i,                               severity: 'medium', label: 'Base64 decode (Python)' },
  { pattern: /Buffer\.from\(.*,\s*['"]base64['"]/i,              severity: 'medium', label: 'Base64 decode (Node)' },
  { pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i,    severity: 'medium', label: 'Hex-encoded payload' },
  // Obfuscation means a LIST of char codes assembled into a hidden string; a single
  // `String.fromCharCode(c)` is how ordinary code turns one byte into a character.
  { pattern: /String\.fromCharCode\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*,\s*(?:0x[0-9a-f]+|\d+)\s*,/i, severity: 'medium', label: 'Character code obfuscation' },

  // Credential stores
  { pattern: /security\s+find-generic-password/i,                severity: 'medium', label: 'macOS Keychain access' },
  { pattern: /security\s+find-internet-password/i,               severity: 'medium', label: 'macOS Keychain internet password' },
  { pattern: /kwallet/i,                                         severity: 'medium', label: 'KDE Wallet access' },
  { pattern: /gnome-keyring/i,                                   severity: 'medium', label: 'GNOME Keyring access' },
  // The concrete tools, not the phrase — "credential manager" appears in prose and
  // in our own type names far more often than the binaries are invoked.
  { pattern: /\bcredential-manager\b|git-credential-manager|\bcmdkey\b/i, severity: 'medium', label: 'Credential manager access' },

  // Data exfiltration patterns
  { pattern: /curl\s+.*-X\s+POST\s+.*-d/i,                      severity: 'medium', label: 'HTTP POST data exfiltration' },
  { pattern: /curl\s+.*--upload-file/i,                          severity: 'medium', label: 'File upload via curl' },
  { pattern: /scp\s+.*@/i,                                       severity: 'medium', label: 'Secure copy to remote host' },
  { pattern: /rsync\s+.*@/i,                                     severity: 'medium', label: 'Rsync to remote host' },
  { pattern: /nc\s+.*<\s*\//i,                                   severity: 'medium', label: 'Netcat file exfiltration' },
  { pattern: /tar\s+.*\|\s*curl/i,                               severity: 'medium', label: 'Archive-and-exfiltrate' },
  { pattern: /pbcopy|xclip|xsel/i,                               severity: 'medium', label: 'Clipboard access' },
  // The capture BINARIES only. The bare word "screenshot" is everywhere in docs,
  // filenames and variable names, and carries no action.
  { pattern: /\bscreencapture\b|\bscrot\b|\bimport\s+-window\s+root\b/i, severity: 'medium', label: 'Screenshot capture' },

  // Network recon & scanning.
  // `nmap` must be its own command word — case-insensitively it also lives inside
  // ordinary identifiers like `tokenMap`.
  { pattern: /(^|[^\w-])nmap\s+/i,                               severity: 'medium', label: 'Network port scanning' },
  { pattern: /masscan\s+/i,                                      severity: 'medium', label: 'Mass port scanning' },
  { pattern: /dig\s+.*@/i,                                       severity: 'medium', label: 'DNS query to specific server' },
  { pattern: /nslookup\s+/i,                                     severity: 'medium', label: 'DNS lookup' },
  { pattern: /ifconfig|ip\s+addr/i,                              severity: 'medium', label: 'Network interface enumeration' },
  { pattern: /netstat\s+-[tulpn]/i,                              severity: 'medium', label: 'Network connection listing' },
  // Two-letter command, so the left boundary is doing all the work — without it
  // `less -N`, `press -t` and friends all matched.
  { pattern: /(^|[^\w-])ss\s+-[a-z]*[tulpn]/i,                   severity: 'medium', label: 'Socket statistics' },
  { pattern: /arp\s+-a/i,                                        severity: 'medium', label: 'ARP table dump' },

  // Process & system recon
  // Answering "which user am I" leaks nothing an agent could not already read.
  { pattern: /whoami/i,                                           severity: 'low',    label: 'User identity check' },
  { pattern: /uname\s+-a/i,                                      severity: 'medium', label: 'System info enumeration' },
  { pattern: /cat\s+\/proc\/(version|cpuinfo|meminfo)/i,         severity: 'medium', label: 'System info via proc' },
  { pattern: /lsof\s+-i/i,                                       severity: 'medium', label: 'Open file/port listing' },
  { pattern: /find\s+\/\s+-perm\s+-4000/i,                       severity: 'medium', label: 'SUID binary search' },
  { pattern: /getcap\s+-r/i,                                     severity: 'medium', label: 'Linux capabilities search' },

  // Python execution
  { pattern: /python[23]?\s+-c\s+["']import/i,                   severity: 'medium', label: 'Python one-liner execution' },
  { pattern: /python[23]?\s+-m\s+http\.server/i,                  severity: 'medium', label: 'Python HTTP server' },
  { pattern: /python[23]?\s+-m\s+SimpleHTTPServer/i,              severity: 'medium', label: 'Python HTTP server (legacy)' },

  // Agent-specific suspicious behavior.
  // Each of these needs a CALL or a direct object, not two words on a line: the
  // old `.*` bridges matched any sentence that happened to mention an agent, a
  // system prompt or safety — which is most of a security codebase's prose.
  { pattern: /\b(?:spawn|fork)\s*\([^\n)]{0,80}agent/i,          severity: 'medium', label: 'Agent self-spawn attempt' },
  { pattern: /(?:modify|edit|overwrite|replace|rewrite|change)\s+(?:your|the\s+agent'?s?|my)\s+system\s*prompt/i, severity: 'medium', label: 'System prompt modification attempt' },
  { pattern: /\boverride\s+(?:the\s+|your\s+|all\s+)?safety\b/i,  severity: 'medium', label: 'Safety override attempt' },
  // A shell profile is only interesting when something WRITES to it. The old
  // alternation also had a precedence bug: the bare `\.zshrc`/`\.profile` branches
  // were not bound to the `write.*to` prefix, so any mention of them fired.
  { pattern: /(?:>>?|\bwrite\b|\bappend\b|\becho\b|\btee\b|\bcat\b|\bsource\b)[^\n]{0,60}(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.zprofile)\b/i, severity: 'medium', label: 'Shell profile modification' },
  { pattern: /\.bash_history|\.zsh_history/i,                     severity: 'medium', label: 'Shell history access' },
  // "keystroke" alone is normal UI vocabulary; the surveillance sense needs the
  // capture verb beside it.
  { pattern: /\bkeylog(?:ger|ging)?\b|\bkeystroke\s+(?:capture|logging|recording|monitor)/i, severity: 'medium', label: 'Keylogging attempt' },

  // ═══════════════════════════════════════════════════════════════════════════
  // LOW — suspicious but frequently legitimate, audit trail
  // ═══════════════════════════════════════════════════════════════════════════

  { pattern: /SELECT\s+\*\s+FROM/i,                              severity: 'low', label: 'Full table scan query' },
  { pattern: /chmod\s+[0-7]*7[0-7]*/i,                           severity: 'low', label: 'World-accessible permission' },
  { pattern: /sudo\s+/i,                                         severity: 'low', label: 'Sudo usage' },
  // The left boundary on the short command names keeps sibling tools out:
  // `pnpm install …` is not npm, `cargo install …` is not `go install`.
  { pattern: /(^|[^\w-])npm\s+install\s+--global/i,              severity: 'low', label: 'Global npm package install' },
  { pattern: /pip\s+install\s+\S/i,                              severity: 'low', label: 'Python package install' },
  { pattern: /(^|[^\w-])npm\s+install\s+\S/i,                    severity: 'low', label: 'npm package install' },
  { pattern: /gem\s+install\s+\S/i,                              severity: 'low', label: 'Ruby gem install' },
  { pattern: /cargo\s+install\s+\S/i,                            severity: 'low', label: 'Rust crate install' },
  { pattern: /(^|[^\w-])go\s+install\s+\S/i,                     severity: 'low', label: 'Go package install' },
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
  // `zip` as its own command — not the tail of `gzip`, `bzip2`, `unzip`, or a
  // `.zip` filename.
  { pattern: /(^|[^\w.\/-])zip\s+/i,                             severity: 'low', label: 'Zip archive operation' },

];

// Combined rule set: CORE built-ins + EXTRA expansion rules (~673 total).
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
