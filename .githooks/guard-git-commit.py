#!/usr/bin/env python3
"""PreToolUse hook (Bash): keep every commit and push Claude makes behind the market data guard.

This is friction, not enforcement. It reads the command text (and the scripts a command runs),
so a determined bypass can still get past it. The GitHub Actions scan and the repository
rulesets are the only enforcement.

Denies a Bash command when it, or a script file it runs, or a git alias it calls:
  - commits with --no-verify or -n, or pushes with --no-verify (skips .githooks/pre-commit or pre-push),
  - sets, overrides, or unsets core.hooksPath (reading it, or setting it to .githooks, is allowed),
  - sets git config through GIT_CONFIG_* environment variables,
  - creates a git alias, or edits git config, that adds --no-verify, -n, or a hooksPath change,
  - mentions MARKET_GUARD_OVERRIDE (only Charlie sets the override, in his own terminal),
  - removes or clears CLAUDECODE (unset, env -u, env -i, env -, exec -c, reassigning it), which
    would make the hooks treat the process as Charlie's terminal,
  - commits or pushes in a repo whose core.hooksPath is not .githooks while .githooks/pre-commit exists.
Exit code 2 blocks the call and shows the reason to Claude.
"""
import json, os, re, shlex, subprocess, sys

OVERRIDE = 'MARKET_GUARD_' + 'OVERRIDE'
TEXT_RULES = [
    (re.compile(re.escape(OVERRIDE)), f'{OVERRIDE} is for Charlie to set in his own terminal. Remove the market figures instead, or ask Charlie.'),
    (re.compile(r'\bunset\b[^;&|\n]*\bCLAUDECODE\b'), 'removing CLAUDECODE would let the hooks accept the override.'),
    (re.compile(r'\benv\b[^;&|\n]*?(?:\s-u\s*CLAUDECODE\b|\s--unset[= ]CLAUDECODE\b|\s-i\b|\s--ignore-environment\b|\s-(?=\s))'),
     'env -u CLAUDECODE, env -i, and env - clear the environment the hooks rely on.'),
    (re.compile(r'(?<![\w$])CLAUDECODE='), 'reassigning CLAUDECODE would let the hooks accept the override.'),
    (re.compile(r'\bexport\s+-n\s+CLAUDECODE\b|\bdeclare\s+\+x\s+CLAUDECODE\b'), 'un-exporting CLAUDECODE would let the hooks accept the override.'),
    (re.compile(r'\bexec\s+-c\b'), 'exec -c clears the environment the hooks rely on.'),
    (re.compile(r'\bGIT_CONFIG_(?:COUNT|PARAMETERS|KEY_\d+|VALUE_\d+|GLOBAL|SYSTEM|NOSYSTEM)\b'), 'git config through GIT_CONFIG_* variables can bypass the hooks.'),
    (re.compile(r'core\.hooks[Pp]ath\s*='), 'overriding core.hooksPath would bypass the market data guard.'),
    (re.compile(r'--unset\S*\s+core\.hooks[Pp]ath'), 'unsetting core.hooksPath would bypass the market data guard.'),
    (re.compile(r'core\.hooks[Pp]ath\s+(?!\.githooks(?:\s|$|[;&|)\'"]))[^\s;&|)]'), 'changing core.hooksPath would bypass the market data guard.'),
    (re.compile(r'(?:\.git/config|\.gitconfig)\b[^\n]*(?:alias|hooks[Pp]ath|no-verify)|(?:alias|hooks[Pp]ath|no-verify)[^\n]*(?:\.git/config|\.gitconfig)\b'),
     'editing git config files to add aliases, hooksPath, or --no-verify would bypass the guard.'),
]
SCRIPT_RUNNERS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'source', '.', 'python', 'python3', 'node', 'perl', 'ruby'}
GIT_GLOBAL_WITH_ARG = {'-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env'}

def deny(reason):
    sys.stderr.write(f'Blocked by the commit guard (guard-git-commit.py): {reason}\n')
    sys.exit(2)

def check_text(text, where):
    for rx, reason in TEXT_RULES:
        if rx.search(text):
            deny(f'{reason} ({where})')

def segments(cmd):
    return [s for s in re.split(r'&&|\|\||;|\||\n|\$\(|`|\)', cmd) if s.strip()]

def words_of(seg):
    try:
        return shlex.split(seg, comments=True)
    except ValueError:
        return seg.split()

def git_config_get(repo, key):
    r = subprocess.run(['git', '-C', repo, 'config', '--get', key], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ''

def check_git(words, cwd, depth, where, repos):
    """words starts at 'git'. Resolve global options and aliases, then judge commit, push, config."""
    i, repo = 1, cwd
    while i < len(words) and words[i].startswith('-'):
        w = words[i]
        if w == '-C' and i + 1 < len(words):
            repo = os.path.join(repo, os.path.expanduser(words[i + 1])); i += 2; continue
        if w in GIT_GLOBAL_WITH_ARG and i + 1 < len(words):
            i += 2; continue
        i += 1
    if i >= len(words):
        return
    sub, args = words[i], words[i + 1:]
    alias = git_config_get(repo, f'alias.{sub}')
    if alias and depth < 5:
        if alias.startswith('!'):
            inspect(alias[1:] + ' ' + ' '.join(shlex.quote(a) for a in args), repo, depth + 1, f'{where}, alias {sub}', repos)
        else:
            check_text(alias, f'{where}, alias {sub}')
            check_git(['git'] + words_of(alias) + args, repo, depth + 1, f'{where}, alias {sub}', repos)
        return
    if sub == 'config':
        keys = [a for a in args if not a.startswith('-')]
        if keys and keys[0].lower().startswith('alias.') and len(keys) > 1:
            value = ' '.join(keys[1:])
            if re.search(r'--no-verify|(?:^|\s)-[a-zA-Z]*n[a-zA-Z]*(?:\s|$)|hooks[Pp]ath', value) or value.startswith('!'):
                deny(f'git alias {keys[0]} would add --no-verify, -n, a hooksPath change, or a shell command ({where}).')
        return
    if sub in ('commit', 'push'):
        skip = False
        for a in args:
            if skip:
                skip = False; continue
            if a in ('-m', '-F', '-c', '-C', '--message', '--file', '--author', '--date', '--push-option', '-o', '--repo'):
                skip = True; continue
            if a == '--no-verify' or (sub == 'commit' and re.fullmatch(r'-[a-zA-Z]*n[a-zA-Z]*', a)):
                deny(f'--no-verify / -n skips the market data guard ({where}).')
        repos.append(repo)

def inspect(cmd, cwd, depth, where, repos):
    check_text(cmd, where)
    if depth > 0 and re.search(r'--no-verify', cmd):
        deny(f'--no-verify inside a script or shell alias skips the market data guard ({where}).')
    for seg in segments(cmd):
        words = words_of(seg)
        while words and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', words[0]):
            words = words[1:]
        if words and words[0] in ('env', 'command', 'exec', 'nohup', 'time', 'sudo'):
            words = [w for w in words[1:] if not w.startswith('-') and '=' not in w]
        if not words:
            continue
        if words[0] in ('bash', 'sh', 'zsh', 'dash', 'ksh') and '-c' in words[1:-1]:
            inspect(words[words.index('-c') + 1], cwd, depth + 1, f'{where}, {words[0]} -c', repos)
            continue
        if 'git' in words:
            check_git(words[words.index('git'):], cwd, depth, where, repos)
        # Script files the command runs: read them and apply the same rules.
        candidates = []
        if words[0] in SCRIPT_RUNNERS:
            candidates = [w for w in words[1:] if not w.startswith('-')][:1]
        elif '/' in words[0] or words[0].endswith(('.sh', '.py')):
            candidates = [words[0]]
        for c in candidates:
            path = os.path.join(cwd, os.path.expanduser(c))
            parent, name = os.path.basename(os.path.dirname(os.path.abspath(path))), os.path.basename(path)
            if parent in ('.githooks', 'githooks', 'hooks') and name in ('pre-commit', 'pre-push', 'guard-git-commit.py'):
                continue  # the committed hooks themselves name the override; they are the guard, not a bypass
            if depth < 3 and os.path.isfile(path) and os.path.getsize(path) < 2_000_000:
                try:
                    text = open(path, encoding='utf-8', errors='ignore').read()
                except OSError:
                    continue
                inspect(text, os.path.dirname(path), depth + 1, f'script {c}', repos)

try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
cmd = (data.get('tool_input') or {}).get('command', '')
cwd = data.get('cwd') or os.getcwd()
repos = []
inspect(cmd, cwd, 0, 'command', repos)
for repo in repos:
    top = subprocess.run(['git', '-C', repo, 'rev-parse', '--show-toplevel'], capture_output=True, text=True).stdout.strip()
    if not top:
        continue
    hp = git_config_get(top, 'core.hooksPath')
    if os.path.isfile(os.path.join(top, '.githooks', 'pre-commit')) and hp != '.githooks':
        deny(f'{top} has .githooks/pre-commit but core.hooksPath is "{hp or "unset"}". Run: git -C {top} config core.hooksPath .githooks')
sys.exit(0)
