import ast
import os
import pathlib
import subprocess

work = pathlib.Path(__file__).resolve().parents[1]
scratch = work / '.review-artifacts/mutation-cli'
source = scratch / 'src/receipt/cli.py'
current = (work / 'src/receipt/cli.py').read_text()
base = subprocess.check_output(['git', 'show', 'origin/release/0.6.x:src/receipt/cli.py'], cwd=work, text=True)
def function(text):
    node = next(n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == '_default_root')
    return node.lineno - 1, node.end_lineno
start, end = function(current)
old_start, old_end = function(base)
lines = current.splitlines(keepends=True)
mutant = ''.join(lines[:start] + base.splitlines(keepends=True)[old_start:old_end] + lines[end:])
source.write_text(mutant)
environment = dict(os.environ, PYTHONPATH=str(scratch / 'src'))
tests = ['test_default_root_refuses_a_dotdot_that_resolves_past_a_link', 'test_default_root_names_the_spec_s_physical_repository_exhaustively']
command = [str(work / '.review-artifacts/ci313/bin/python'), '-m', 'pytest', '-q', '--tb=short', '--basetemp', str(scratch / 'properties-temp'), *[f'tests/test_cli.py::{name}' for name in tests]]
try:
    result = subprocess.run(command, cwd=scratch, env=environment, capture_output=True, text=True)
    (work / '.review-artifacts/cli-properties-mutant.log').write_text(result.stdout + result.stderr)
    print('command:', ' '.join(command))
    print('exit:', result.returncode)
    print(result.stdout)
finally:
    source.write_text(current)
