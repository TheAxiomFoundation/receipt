import os
import pathlib
import shutil
import subprocess
import sys

work = pathlib.Path(__file__).resolve().parents[1]
scratch = work / '.review-artifacts/mutation-cli'
scratch.mkdir(exist_ok=True)
for directory in ('src', 'tests'):
    shutil.copytree(work / directory, scratch / directory, dirs_exist_ok=True)
shutil.copy2(work / 'pyproject.toml', scratch / 'pyproject.toml')
source = scratch / 'src/receipt/cli.py'
current = source.read_text()
base = subprocess.check_output(['git', 'show', 'origin/release/0.6.x:src/receipt/cli.py'], cwd=work, text=True)
tests = [
    'test_default_root_refuses_a_spec_named_through_a_committed_symlink',
    'test_default_root_refusal_survives_spec_and_anchor_pins',
    'test_default_root_ignores_links_above_the_repository_top_level',
    'test_default_root_refuses_a_top_level_named_through_a_symlink',
    'test_default_root_refuses_a_dotdot_that_resolves_past_a_link',
    'test_default_root_names_the_spec_s_physical_repository_exhaustively',
]
environment = dict(os.environ)
environment['PYTHONPATH'] = str(scratch / 'src')
def run(label, content, names):
    source.write_text(content)
    command = [sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=', *[f'tests/test_cli.py::{test}' for test in names]]
    result = subprocess.run(command, cwd=scratch, env=environment, capture_output=True, text=True)
    (work / f'.review-artifacts/cli-{label}.log').write_text(result.stdout + result.stderr)
    print(label, 'command:', ' '.join(command), flush=True)
    print(label, 'exit:', result.returncode, flush=True)
    print(result.stdout[-3500:], flush=True)
    return result
try:
    run('baseline', base, tests)
    reject_ambient = current.replace('for directory in walked:', 'for directory in (named.parent, *named.parent.parents):')
    assert reject_ambient != current
    run('reject-ambient', reject_ambient, ['test_default_root_ignores_links_above_the_repository_top_level'])
finally:
    source.write_text(current)
