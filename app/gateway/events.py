"""Local event spool — the gateway's store-and-forward evidence queue.

The gateway is a sensor, the Cloud is the ledger (GATEWAY_EVENT_CACHE.md).
While the Cloud is unreachable the agent keeps observing — peers added and
removed, a handshake advancing, NAT rules failing — and appends each event
here rather than losing it. When the link returns the batch endpoint drains
the spool, and the agent trims it only after a 2xx, so a lost response means
the rows are sent twice and counted once.

Constraints this file exists to honour:

* **Append-only JSON Lines, one event per line.** A power cut can lose the
  tail of the queue, never the queue itself.
* **uuid4 minted at record time, not a sequence counter.** The crash window
  between "increment" and "persist" would silently drop or duplicate events;
  a uuid the box cannot reuse makes resend-safe dedup the server's problem to
  solve once, not ours to get right under a power cut.
* **Best-effort, always.** A full or unwritable disk degrades to "we lost
  some evidence" and logs; it must never raise into the tunnel loop. Evidence
  loss beats tunnel loss.
* **Single writer** — the agent's main loop. The lock is belt-and-braces in
  case a second emitter is added later.
"""
import json
import os
import threading
import uuid
from datetime import datetime, timezone

DEFAULT_PATH = "/var/lib/odivora/events.jsonl"

# Consecutive write failures before the spool gives up for this run: a path
# that does not exist and cannot be created must not be retried forever, while
# a transient ENOSPC should recover on its own.
_MAX_FAILURES = 5


def _utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_event(event_type: str, payload: dict | None = None) -> dict:
    """Build the envelope every spooled event carries."""
    return {"event_id": str(uuid.uuid4()), "recorded_at": _utc_iso(),
            "type": str(event_type)[:60], "payload": payload or {}}


class EventSpool:
    """Bounded, rotating JSONL queue living next to the agent's state file."""

    def __init__(self, path: str = DEFAULT_PATH, *, rotate_bytes: int = 1_000_000,
                 rotate_lines: int = 5000, keep_rotated: int = 3,
                 max_bytes: int = 5_000_000):
        self.path = path
        self.rotate_bytes = rotate_bytes
        self.rotate_lines = rotate_lines
        self.keep_rotated = keep_rotated
        self.max_bytes = max_bytes
        self.broken = False
        self._failures = 0
        self._lines: int | None = None  # counted lazily, then maintained
        self._lock = threading.Lock()

    # --- writing ---

    def emit(self, event_type: str, payload: dict | None = None) -> dict | None:
        if self.broken:
            return None
        event = new_event(event_type, payload)
        with self._lock:
            try:
                self._append(event)
                self._enforce()
            except OSError as exc:
                self._failures += 1
                print(f"[spool] write failed ({self._failures}/{_MAX_FAILURES}): {exc}",
                      flush=True)
                if self._failures >= _MAX_FAILURES:
                    self.broken = True
                    print("[spool] giving up: events will be lost until restart", flush=True)
                return None
            self._failures = 0
        return event

    def _append(self, event: dict) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        line = json.dumps(event, separators=(",", ":"), default=str)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        if self._lines is None:
            self._lines = self._count_lines()  # includes the line just written
        else:
            self._lines += 1

    # --- bounding ---

    def probe(self) -> bool:
        """Can we append here? Creates the directory/file, writes nothing."""
        try:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            with open(self.path, "a", encoding="utf-8"):
                pass
            return True
        except OSError:
            return False

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _rotated(self) -> list[str]:
        """Rotated files, oldest first.

        Ordered by the sequence number baked into the name, never by mtime:
        an ack rewrites a segment and refreshes its mtime, which would push an
        older segment behind a newer one and ship the backlog out of order.
        """
        directory = os.path.dirname(self.path) or "."
        prefix = os.path.basename(self.path).split(".")[0] + "-"
        try:
            names = [n for n in os.listdir(directory) if n.startswith(prefix)]
        except OSError:
            return []
        def key(name: str):
            seq = name[len(prefix):].split("-")[0]
            return (int(seq) if seq.isdigit() else 0, name)
        return [os.path.join(directory, n) for n in sorted(names, key=key)]

    def _next_seq(self) -> int:
        """Next rotation sequence, continuing from whatever is on disk."""
        prefix = os.path.basename(self.path).split(".")[0] + "-"
        highest = 0
        for path in self._rotated():
            name = os.path.basename(path)
            token = name[len(prefix):].split("-")[0] if name.startswith(prefix) else ""
            if token.isdigit():
                highest = max(highest, int(token))
        return highest + 1

    def _segments(self) -> list[str]:
        """Every file the queue lives in, oldest first, active last."""
        paths = self._rotated()
        if os.path.exists(self.path):
            paths.append(self.path)
        return paths

    def _count_lines(self) -> int:
        if not os.path.exists(self.path):
            return 0
        with open(self.path, "rb") as f:
            return sum(1 for _ in f)

    def _enforce(self) -> None:
        """Rotate, then bound the queue — always loudly.

        Rotation is not a drop: segments stay shippable (see `_segments`), so
        the only way an event leaves here unsent is the byte cap, the segment
        count, or a shed inside the active file. Every one of those appends a
        `spool_overflow` marker: a gap that announces itself is auditable, a
        silent one is not — and a marker that is itself shed hands its counts
        forward, so the announced gap never shrinks.
        """
        if self._lines is None:
            self._lines = self._count_lines()
        if self._lines >= self.rotate_lines or self._size() >= self.rotate_bytes:
            self._rotate()
        dropped = dropped_bytes = 0
        while True:
            rotated = self._rotated()
            if not rotated:
                break
            over_bytes = (self._size() + sum(_safe_size(p) for p in rotated)
                          > self.max_bytes)
            if not (over_bytes or len(rotated) > self.keep_rotated):
                break
            victim = rotated[0]
            freed = _safe_size(victim)
            rows, carried, carried_bytes = _tally(_read_lines(victim))
            try:
                os.remove(victim)
            except OSError:
                break
            dropped += rows + carried
            dropped_bytes += freed + carried_bytes
        rotated_total = sum(_safe_size(p) for p in self._rotated())
        if self._size() + rotated_total > self.max_bytes:
            victims, freed = self._shed_oldest(limit=self.max_bytes - rotated_total)
            rows, carried, carried_bytes = _tally(victims)
            dropped += rows + carried
            dropped_bytes += freed + carried_bytes
        if dropped or dropped_bytes:
            # Written directly rather than via emit() to avoid re-entering
            # _enforce; a marker must never be the thing that overflows.
            self._write_line(new_event("spool_overflow",
                                       {"dropped": dropped, "bytes": dropped_bytes}))

    def _rotate(self) -> None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = os.path.basename(self.path).split(".")[0]
        directory = os.path.dirname(self.path) or "."
        # Sequence first, timestamp second: the sequence is what keeps segments
        # in order, the timestamp is what tells a human when they were cut.
        seq = self._next_seq()
        dest = os.path.join(directory, f"{base}-{seq:06d}-{stamp}.jsonl")
        while os.path.exists(dest):
            seq += 1
            dest = os.path.join(directory, f"{base}-{seq:06d}-{stamp}.jsonl")
        os.replace(self.path, dest)
        self._lines = 0

    def _shed_oldest(self, limit: int) -> tuple[list[bytes], int]:
        """Keep the newest contiguous run that fits in `limit`.

        Contiguous on purpose: dropping a line from the middle while keeping
        older ones leaves a gap in the middle of the history, which reads like
        two incidents. Returns (the dropped lines, bytes freed).
        """
        with open(self.path, "rb") as f:
            lines = f.readlines()
        kept: list[bytes] = []
        victims: list[bytes] = []
        size = 0
        full = False
        for line in reversed(lines):  # newest first
            if full or (size + len(line) > limit and kept):
                full = True
                victims.append(line)
                continue
            kept.append(line)
            size += len(line)
        kept.reverse()
        self._write_atomic(b"".join(kept), self.path)
        self._lines = len(kept)
        return victims, sum(len(v) for v in victims)

    def _write_line(self, event: dict) -> None:
        """Append one already-built event without going through _enforce."""
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":"), default=str) + "\n")
            f.flush()
        if self._lines is not None:
            self._lines += 1

    def _write_atomic(self, data: bytes, path: str | None = None) -> None:
        path = path or self.path
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # --- reading / shipping ---

    def _load(self, path: str) -> list[tuple[str, str]]:
        """(event_id, raw_line) for parseable lines; corrupt lines are dropped.

        A truncated last line after a power cut is expected, not an error: it
        is skipped and disappears on the next rewrite of that segment.
        """
        if not os.path.exists(path):
            return []
        out = []
        try:
            handle = open(path, encoding="utf-8")
        except OSError:
            return []
        with handle as f:
            for raw in f:
                line = raw.rstrip("\n")
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    print(f"[spool] skipping bad line ({len(line)} bytes)", flush=True)
                    continue
                if not isinstance(event, dict) or "type" not in event or "event_id" not in event:
                    print("[spool] skipping malformed event", flush=True)
                    continue
                out.append((str(event["event_id"]), line))
        return out

    def _read_all(self) -> list[tuple[str, str, str]]:
        """(path, event_id, raw line) across every segment, oldest first."""
        return [(path, eid, line)
                for path in self._segments()
                for eid, line in self._load(path)]

    def pending(self) -> list[dict]:
        return [json.loads(line) for _, _, line in self._read_all()]

    def batch(self, max_events: int = 200, max_bytes: int = 262144) -> list[dict]:
        """The next shippable slice of the queue, oldest first."""
        events: list[dict] = []
        size = 0
        for _, _, line in self._read_all():
            if len(events) >= max_events or (events and size + len(line) > max_bytes):
                break
            size += len(line)
            events.append(json.loads(line))
        return events

    def ack(self, events) -> None:
        """Trim the queue after the server confirmed a batch.

        Rewrites each segment that held an acknowledged event minus those ids
        (new emits may have landed since the batch was read), which also
        discards any corrupt line found along the way. Untouched segments keep
        their bytes — history nobody acked is not rewritten for fun.
        """
        if not events:
            return
        with self._lock:
            done = {str(e.get("event_id")) for e in events if isinstance(e, dict)}
            if not done:
                return
            for path in self._segments():
                entries = self._load(path)
                if not entries or not any(eid in done for eid, _ in entries):
                    continue
                keep = [line for eid, line in entries if eid not in done]
                if not keep and path != self.path:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    continue
                self._write_atomic(
                    b"".join(l.encode("utf-8") + b"\n" for l in keep), path)
            self._lines = self._count_lines()

    def depth(self) -> int:
        with self._lock:
            return len(self._read_all())


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _read_lines(path: str) -> list[bytes]:
    try:
        with open(path, "rb") as f:
            return f.readlines()
    except OSError:
        return []


def _tally(lines) -> tuple[int, int, int]:
    """(evidence rows, carried rows, carried bytes) for content being dropped.

    A `spool_overflow` marker that is itself dropped hands its totals forward,
    so the next marker keeps counting rows lost before it existed. Without
    that, every shed would shrink the very gap it is supposed to announce.
    """
    rows = carried = carried_bytes = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            rows += 1
            continue
        if isinstance(event, dict) and event.get("type") == "spool_overflow":
            payload = event.get("payload") or {}
            carried += int(payload.get("dropped") or 0)
            carried_bytes += int(payload.get("bytes") or 0)
        else:
            rows += 1
    return rows, carried, carried_bytes


def spool_from_env(env: dict | None = None, default_path: str = DEFAULT_PATH,
                   fallback_dir: str | None = None) -> EventSpool:
    """Build a spool from the agent's config; missing path setting => default.

    If the configured path cannot be appended to (fresh box, no /var/lib yet,
    non-root dev run) the queue falls back next to the agent's state file —
    GATEWAY_EVENT_CACHE.md §2 — and only reports "no spool" when that fails
    too, so the caller never loses evidence to an unwritable default.
    """
    source = env if env is not None else os.environ
    path = source.get("EVENT_SPOOL") or default_path
    spool = EventSpool(path)
    if spool.probe():
        return spool
    if fallback_dir:
        alt = EventSpool(os.path.join(fallback_dir, os.path.basename(path)))
        if alt is not None and alt.path != spool.path and alt.probe():
            print(f"[spool] {spool.path} not writable; using {alt.path}", flush=True)
            return alt
    print(f"[spool] no writable path for {path}; events will be lost", flush=True)
    spool.broken = True
    return spool

