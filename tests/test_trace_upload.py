"""Publishing Frame agent traces to a HF dataset (frame/sil/trace_upload.py).

Collects only valid STS traces, names them readably, and builds a tagged dataset card.
The upload itself needs huggingface_hub + a token and a public repo; these offline tests
cover everything up to the network call (dry_run)."""

from frame.sil.trace_upload import collect_traces, dataset_card, upload_traces
from frame.sil.llm_trace import TraceWriter


def _trace(path, sid="s1"):
    w = TraceWriter(path, sid, name="run")
    w.start()
    w.append_message({"role": "system", "content": "sys"})
    w.append_message({"role": "user", "content": "go"})
    w.append_message({"role": "assistant", "content": "done"})


def test_collect_finds_sts_traces_and_names_them(tmp_path):
    # Mirror the run layout: <dir>/traj/<case>/<checkout>/hunt.jsonl
    d = tmp_path / "traj" / "open-webui-x" / "vulnerable"
    d.mkdir(parents=True)
    _trace(str(d / "hunt.jsonl"))
    # a timing sidecar + a non-trace file must be ignored
    (d / "hunt.jsonl.calls.jsonl").write_text('{"status":"ok"}\n')
    (tmp_path / "notes.txt").write_text("ignore me")
    found = collect_traces(str(tmp_path))
    assert len(found) == 1
    name, path, header = found[0]
    assert name == "open-webui-x__vulnerable.jsonl"      # flat, readable
    assert header["harness"] == "frame"


def test_non_sts_jsonl_is_skipped(tmp_path):
    (tmp_path / "random.jsonl").write_text('{"foo": 1}\n{"bar": 2}\n')   # no session header
    assert collect_traces(str(tmp_path)) == []


def test_dataset_card_is_tagged_as_agent_traces():
    card = dataset_card(5, ["frame"], ["python", "typescript"])
    assert card.startswith("---")                        # YAML frontmatter
    assert "pretty_name: Frame Agent Traces" in card
    assert "- agent-traces" in card and "- frame" in card
    assert "- python" in card and "- typescript" in card
    assert "session-traces-format" in card               # points at the HF spec
    assert "harness: frame" in card


def test_dry_run_validates_without_uploading(tmp_path):
    d = tmp_path / "traj" / "wger-y" / "fixed"
    d.mkdir(parents=True)
    _trace(str(d / "hunt.jsonl"))
    res = upload_traces(str(tmp_path), "lambdasec/frame-agent-traces", dry_run=True)
    assert res["dry_run"] is True and res["n_traces"] == 1
    assert res["names"] == ["wger-y__fixed.jsonl"]
    assert "uploaded" not in res                          # nothing pushed


def test_empty_dir_uploads_nothing(tmp_path):
    res = upload_traces(str(tmp_path), "lambdasec/frame-agent-traces")
    assert res["uploaded"] == 0
