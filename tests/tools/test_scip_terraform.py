"""Tests for the scip_terraform indexer (terraform-ls → SCIP bridge).

terraform-ls isn't available in unit-test env, so the LSPClient is mocked with
canned documentSymbol / references responses. Validates:
  * descriptor + symbol-string construction from terraform-ls symbol names
  * hierarchical + flat documentSymbol flattening
  * the emitted .scip round-trips through scip_pb2 with correct def/ref roles
  * CROSS-FILE reference resolution (a var defined in variables.tf, referenced
    in main.tf, lands as a reference occurrence on main.tf) — the whole point
    of using a language server over a raw HCL walk.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

from strix.tools.code_graph.scip_terraform import emit, indexer, scip_pb2


def test_descriptor_from_documentsymbol_names():
    assert indexer._descriptor('resource "aws_s3_bucket" "logs"', 23) == "resource/aws_s3_bucket/logs#"
    assert indexer._descriptor('variable "region"', 13) == "variable/region."
    assert indexer._descriptor('module "vpc"', 5) == "module/vpc#"


def test_symbol_string_scheme():
    assert emit.make_symbol("resource/aws_s3_bucket/logs#") == \
        "scip-terraform . . . resource/aws_s3_bucket/logs#"


def test_flatten_hierarchical_and_flat():
    flat: list[dict] = []
    indexer._flatten_symbols([
        {"name": 'variable "r"', "kind": 13,
         "location": {"range": {"start": {"line": 1, "character": 0},
                                "end": {"line": 1, "character": 5}}}},
        {"name": 'resource "x" "y"', "kind": 23,
         "range": {"start": {"line": 3, "character": 0}, "end": {"line": 3, "character": 8}},
         "children": [{"name": "attr", "kind": 8,
                       "selectionRange": {"start": {"line": 4, "character": 2},
                                          "end": {"line": 4, "character": 6}}}]},
    ], flat)
    assert len(flat) == 3


def test_emit_roundtrips_with_roles(tmp_path):
    sym = "scip-terraform . . . resource/aws_s3_bucket/logs#"
    docs = [emit.Document(
        relative_path="main.tf",
        occurrences=[emit.Occurrence(sym, 3, 9, 20, is_definition=True),
                     emit.Occurrence(sym, 30, 15, 26, is_definition=False)],
        defined_symbols={sym})]
    out = emit.write_index(emit.build_index(docs, project_root=tmp_path), tmp_path / "tf.scip")
    idx = scip_pb2.Index()
    idx.ParseFromString(out.read_bytes())
    assert len(idx.documents) == 1
    occ = idx.documents[0].occurrences
    assert occ[0].symbol_roles == 0x1 and list(occ[0].range) == [3, 9, 20]  # def
    assert occ[1].symbol_roles == 0                                          # ref
    assert len(idx.documents[0].symbols) == 1


class _FakeLSP:
    def __init__(self, cmd, root, **kw):
        self.root = Path(root)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def did_open(self, *a, **k):
        pass

    def document_symbol(self, path):
        if path.name == "variables.tf":
            return [{"name": 'variable "region"', "kind": 13,
                     "range": {"start": {"line": 0, "character": 9},
                               "end": {"line": 0, "character": 17}}}]
        if path.name == "main.tf":
            return [{"name": 'resource "aws_s3_bucket" "b"', "kind": 23,
                     "range": {"start": {"line": 0, "character": 9},
                               "end": {"line": 0, "character": 24}}}]
        return []

    def references(self, path, line, char, include_declaration=False):
        if path.name == "variables.tf":
            return [{"uri": (self.root / "main.tf").as_uri(),
                     "range": {"start": {"line": 2, "character": 11},
                               "end": {"line": 2, "character": 24}}}]
        return []


def test_index_resolves_cross_file_references(tmp_path):
    (tmp_path / "variables.tf").write_text('variable "region" {\n  default = "us-east-2"\n}\n')
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  region = var.region\n}\n')
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with mock.patch.object(indexer, "LSPClient", _FakeLSP):
        scip_path = indexer.index(tmp_path, out_dir)
    assert scip_path is not None
    idx = scip_pb2.Index()
    idx.ParseFromString(scip_path.read_bytes())
    paths = {d.relative_path for d in idx.documents}
    assert {"main.tf", "variables.tf"} <= paths
    var_defs = [o for d in idx.documents if d.relative_path == "variables.tf"
                for o in d.occurrences if o.symbol_roles == 0x1]
    main_refs = [o for d in idx.documents if d.relative_path == "main.tf"
                 for o in d.occurrences if "region" in o.symbol and o.symbol_roles == 0]
    assert len(var_defs) >= 1
    assert len(main_refs) >= 1  # cross-file reference resolved


def test_index_returns_none_without_terraform(tmp_path):
    (tmp_path / "main.py").write_text("print('no terraform here')\n")
    assert indexer.index(tmp_path, tmp_path) is None
