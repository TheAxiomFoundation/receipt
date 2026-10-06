"""Raw pre-genesis append subjects using the existing observation-row schema."""
import hashlib
import json

import pytest

from m1_fixture import RawRepo
from test_append_gate import GATE_SPEC, observation_row, jsonl_line


@pytest.fixture
def append_repo(tmp_path):
    repo = RawRepo(tmp_path / "append")
    rows = [observation_row(number) for number in (1, 2)]
    lines = [jsonl_line(row) for row in rows]
    prefix = {"schemaVersion": GATE_SPEC.prefix_schema_version, "prefixLineCount": 1,
              "lineSha256s": [hashlib.sha256(lines[0].encode()).hexdigest()],
              "prefixSha256": hashlib.sha256((lines[0] + "\n").encode()).hexdigest()}
    repo.base = repo.commit(((GATE_SPEC.chain.state_relative.as_posix(), "100644", ("\n".join(lines) + "\n").encode()),
                            (GATE_SPEC.chain.prefix_relative.as_posix(), "100644", (json.dumps(prefix) + "\n").encode()),
                            ("releases/README.md", "100644", b"releases\n")))
    repo.git("update-ref", "HEAD", repo.base)
    return repo
