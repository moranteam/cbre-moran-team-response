#!/usr/bin/env python3
"""PreToolUse hook (Bash): keep every commit Claude makes, /inbox included, behind the market data guard.

Denies a Bash command when it:
  - commits with --no-verify or -n (skips .githooks/pre-commit),
  - sets or unsets core.hooksPath (points git away from .githooks),
  - sets MARKET_GUARD_OVERRIDE (only Charlie sets the override, in his own terminal),
  - runs git commit in a repo whose core.hooksPath is not .githooks.
Exit code 2 blocks the call and shows the reason to Claude.
"""
import json, os, re, shlex, subprocess, sys

try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
cmd = (data.get('tool_input') or {}).get('command', '')
cwd = data.get('cwd') or os.getcwd()
if 'git' not in cmd and 'MARKET_GUARD_OVERRIDE' not in cmd:
    sys.exit(0)

def deny(reason):
    sys.stderr.write(f'Blocked by hooks/guard-git-commit.py: {reason}\n')
    sys.exit(2)

if 'MARKET_GUARD_OVERRIDE' in cmd:
    deny('MARKET_GUARD_OVERRIDE is for Charlie to set in his own terminal. Remove the market figures instead, or ask Charlie.')
# Reading core.hooksPath, or setting it to .githooks, is fine. Any other value, -c overrides, or unset is not.
if (re.search(r'core\.hooks[Pp]ath\s*=', cmd)
        or re.search(r'--unset\S*\s+core\.hooks[Pp]ath', cmd)
        or re.search(r'core\.hooks[Pp]ath\s+(?!\.githooks(?:\s|$|[;&|)]))[^\s;&|)]', cmd)):
    deny('changing core.hooksPath would bypass the market data guard.')

commits = []
for part in re.split(r'&&|\|\||;|\|', cmd):
    try:
        words = shlex.split(part)
    except ValueError:
        words = part.split()
    if 'git' not in words:
        continue
    words = words[words.index('git'):]
    if 'commit' not in words:
        continue
    repo = cwd
    for i, w in enumerate(words[:words.index('commit')]):
        if w == '-C' and i + 1 < len(words):
            repo = os.path.join(repo, os.path.expanduser(words[i + 1]))
    args = words[words.index('commit') + 1:]
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a in ('-m', '-F', '-c', '-C', '--message', '--file', '--author', '--date'):
            skip = True
            continue
        if a == '--no-verify' or re.fullmatch(r'-[a-zA-Z]*n[a-zA-Z]*', a):
            deny('--no-verify / -n skips the market data guard.')
    commits.append(repo)

for repo in commits:
    top = subprocess.run(['git', '-C', repo, 'rev-parse', '--show-toplevel'], capture_output=True, text=True).stdout.strip()
    if not top:
        continue
    hp = subprocess.run(['git', '-C', top, 'config', 'core.hooksPath'], capture_output=True, text=True).stdout.strip()
    if os.path.isfile(os.path.join(top, '.githooks', 'pre-commit')) and hp != '.githooks':
        deny(f'{top} has .githooks/pre-commit but core.hooksPath is "{hp or "unset"}". Run: git -C {top} config core.hooksPath .githooks')
sys.exit(0)
