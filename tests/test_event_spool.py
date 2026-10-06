"""Agent-side event spool: the gateway's store-and-forward evidence queue.

What has to be true of the file the gateway appends to while the Cloud is
unreachable (GATEWAY_EVENT_CACHE.md §2):

  * it round-trips every event it was given, one JSON object per line;
  * a half-written line after a power cut is skipped, never fatal;
  * bounding (rotation, segment count, byte cap) never silently loses a row —
    what is dropped is counted in a `spool_overflow` marker;
  * rotation does not orphan rows: segments stay shippable, oldest first, so
    the whole backlog drains after reconnecting;
  * ack trims only what the server confirmed, across every segment;
  * it holds events and nothing else — no token ever reaches the file.
"""
import json
import os
import threading
import uuid
from datetime import datetime

import pytest

from app.gateway.events import EventSpool, new_event, spool_from_env


def _lines(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError:
        return []


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _ids(events):
    return [e["event_id"] for e in events]


@pytest.fixture
def spool(tmp_path):
    return EventSpool(str(tmp_path / "events.jsonl"))


# ------------------------------------------------------------- round trip ---

def test_an_event_survives_the_write_read_round_trip(spool):
    emitted = spool.emit("peer_added", {"peer_public_key": "abc", "allowed_ip": "10.8.0.3"})

    assert spool.pending() == [emitted]
    assert spool.depth() == 1
    assert len(_lines(spool.path)) == 1  # one JSON object per line
    assert json.loads(_lines(spool.path)[0]) == emitted

    assert str(uuid.UUID(emitted["event_id"])) == emitted["event_id"]
    # The gateway's clock, in a form the server can parse without guessing.
    assert emitted["recorded_at"].endswith("Z")
    datetime.fromisoformat(emitted["recorded_at"].replace("Z", "+00:00"))


def test_the_envelope_has_no_slot_for_anything_but_the_event(spool):
    """Tokens and keys live in state.json, not here: the shape is fixed, so a
    careless emitter cannot add a top-level credential to the queue."""
    spool.emit("token_refreshed", {"gateway_id": "b7e0"})

    event = json.loads(_lines(spool.path)[0])
    assert set(event) == {"event_id", "recorded_at", "type", "payload"}
    assert "Bearer" not in _lines(spool.path)[0]
    assert "GATEWAY_TOKEN" not in _lines(spool.path)[0]


def test_the_event_type_is_bounded_but_the_payload_is_left_for_the_server():
    event = new_event("t" * 500, {"detail": "x" * 400})
    assert len(event["type"]) == 60


# ------------------------------------------------------------- corruption ---

def test_a_truncated_line_is_skipped_and_disappears_on_the_next_rewrite(spool):
    with open(spool.path, "a", encoding="utf-8") as f:
        f.write(json.dumps(new_event("peer_added")) + "\n")
        f.write('{"event_id": "b7e0')   # power cut mid-append, no newline
        f.write("not json at all\n")
        f.write("\n")

    survivor = spool.emit("peer_removed", {})

    assert _ids(spool.pending()) == [json.loads(_lines(spool.path)[0])["event_id"],
                                     survivor["event_id"]]
    # Ack rewrites the segment: the garbage line is gone for good.
    spool.ack([survivor])
    assert len(_lines(spool.path)) == 1
    assert json.loads(_lines(spool.path)[0])["type"] == "peer_added"


# --------------------------------------------------------------- rotation ---

def test_rotation_keeps_every_row_shippable_and_in_order(tmp_path):
    """Rotation is a size boundary, not a loss: an outage that fills the
    active file must still drain whole once the Cloud returns."""
    spool = EventSpool(str(tmp_path / "events.jsonl"),
                       rotate_lines=3, keep_rotated=10, max_bytes=10_000_000)
    ids = [spool.emit("handshake_seen", {"n": i})["event_id"] for i in range(10)]

    assert len(spool._rotated()) == 3          # rolled at 3, 6, 9
    assert len(_lines(spool.path)) == 1        # active file holds the tail
    assert _ids(spool.pending()) == ids        # oldest segment first
    assert spool.depth() == 10


def test_the_segment_count_is_bounded_and_the_loss_is_marked(tmp_path):
    spool = EventSpool(str(tmp_path / "events.jsonl"),
                       rotate_lines=2, keep_rotated=1, max_bytes=10_000_000)
    ids = [spool.emit("peer_added", {"n": i})["event_id"] for i in range(6)]

    assert len(spool._rotated()) <= 1
    kept = [e for e in spool.pending() if e["type"] != "spool_overflow"]
    assert ids[0] not in _ids(kept)          # the oldest segment went
    assert kept[-1]["event_id"] == ids[-1]   # and it was the oldest that went
    marker = [e for e in spool.pending() if e["type"] == "spool_overflow"]
    assert marker and marker[0]["payload"]["dropped"] >= 1


# ------------------------------------------------------------------- cap ----

def test_the_byte_cap_drops_the_oldest_segment_with_a_marker(tmp_path):
    spool = EventSpool(str(tmp_path / "events.jsonl"), rotate_bytes=400,
                       rotate_lines=100, keep_rotated=10, max_bytes=1000)
    ids = [spool.emit("sync_error", {"n": i, "pad": "x" * 200})["event_id"]
           for i in range(8)]

    files = spool._segments()
    assert sum(_size(p) for p in files) <= 1000 + 200  # cap + one marker line
    assert ids[0] not in _ids(spool.pending())
    marker = [e for e in spool.pending() if e["type"] == "spool_overflow"]
    assert marker, "a dropped row must announce itself"
    assert marker[0]["payload"]["dropped"] >= 1
    assert marker[0]["payload"]["bytes"] >= 1


def test_shedding_inside_the_active_file_keeps_a_contiguous_newest_run(tmp_path):
    """Dropping from the middle of the history would read as two incidents."""
    spool = EventSpool(str(tmp_path / "events.jsonl"), rotate_lines=10 ** 6,
                       rotate_bytes=10 ** 7, max_bytes=600)
    ids = [spool.emit("wan_ip_changed", {"n": i, "pad": "x" * 200})["event_id"]
           for i in range(6)]

    kept = [e["event_id"] for e in spool.pending() if e["type"] != "spool_overflow"]
    assert 0 < len(kept) < 6
    assert kept == ids[len(ids) - len(kept):]
    markers = [e for e in spool.pending() if e["type"] == "spool_overflow"]
    assert markers and all(m["payload"]["dropped"] >= 1 for m in markers)
    assert sum(m["payload"]["dropped"] for m in markers) >= 6 - len(kept)


# --------------------------------------------------------------- acking ----

def test_ack_trims_across_segments_and_leaves_everything_else_alone(tmp_path):
    spool = EventSpool(str(tmp_path / "events.jsonl"), rotate_lines=3,
                       keep_rotated=10, max_bytes=10_000_000)
    ids = [spool.emit("peer_removed", {"n": i})["event_id"] for i in range(10)]
    first_five = [e for e in spool.pending() if e["event_id"] in ids[:5]]

    spool.ack(first_five)

    assert _ids(spool.pending()) == ids[5:]
    # A batch the server never confirmed is untouched.
    assert set(ids[5:]) == set(_ids(spool.pending()))


def test_ack_of_an_empty_batch_is_a_noop(spool):
    spool.emit("agent_started", {})
    before = _lines(spool.path)
    spool.ack([])
    assert _lines(spool.path) == before


# ------------------------------------------------------- single writer ------

def test_emitters_from_several_threads_never_corrupt_the_queue(tmp_path):
    """Two open handles on one JSONL file interleave bytes; the lock is the
    rule, not an optimisation."""
    spool = EventSpool(str(tmp_path / "events.jsonl"))

    def work(worker):
        for i in range(25):
            spool.emit("handshake_seen", {"w": worker, "i": i})

    threads = [threading.Thread(target=work, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    events = spool.pending()
    assert len(events) == 100
    assert len({e["event_id"] for e in events}) == 100


# ------------------------------------------------------- unwritable path ----

def test_an_unwritable_path_degrades_instead_of_raising(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")
    spool = EventSpool(str(blocker / "events.jsonl"))

    for _ in range(5):
        assert spool.emit("peer_added", {}) is None
    assert spool.broken is True          # gave up rather than retry forever
    assert spool.emit("peer_added", {}) is None


def test_the_queue_falls_back_next_to_the_state_file(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")
    fallback_dir = tmp_path / "etc"
    fallback_dir.mkdir()

    spool = spool_from_env({"EVENT_SPOOL": str(blocker / "events.jsonl")},
                           fallback_dir=str(fallback_dir))

    assert spool.path == str(fallback_dir / "events.jsonl")
    assert spool.emit("agent_started", {}) is not None
    assert spool.depth() == 1


def test_no_writable_path_anywhere_marks_the_queue_broken(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory")

    spool = spool_from_env({"EVENT_SPOOL": str(blocker / "events.jsonl")},
                           fallback_dir=str(blocker / "sub"))

    assert spool.broken is True
    assert spool.emit("agent_started", {}) is None
