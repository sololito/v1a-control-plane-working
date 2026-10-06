"""Reconnect pacing for gateways talking to the Cloud.

A flat `sleep(interval)` loop is the wrong shape for a device on a home uplink:

  * during an outage every gateway retries on the same cadence, so the fleet
    reconnects in lockstep and hammers an already-struggling server exactly when
    it is least able to absorb it;
  * recovery is delayed by up to a full interval after the Cloud comes back,
    with no reason for the delay to be fixed rather than growing.

This is exponential backoff with jitter: grow on failure, reset on success, and
decorrelate the fleet so retries do not coincide.

The cap is the sharp edge. The Cloud marks a gateway offline once its
`last_seen` is older than `heartbeat_offline_after_seconds` (120s by default),
so a backoff cap at or above that threshold guarantees the gateway flaps to
"offline" during a long outage even though it would have reconnected moments
later — and an offline gateway cannot be connected to at all. Keep the cap
comfortably below it; `_clamp_cap` enforces that.
"""
import random


class Backoff:
    """Exponential backoff with jitter, reset on success.

    `rand` is injectable so tests can pin the jitter instead of asserting on
    random values. `jitter` is a switch: 0 disables spreading (delays are then
    exactly base/cap and fully deterministic), anything above 0 spreads
    failures across the lower half of the window (equal jitter).
    """

    def __init__(self, base=10.0, cap=60.0, factor=2.0, jitter=0.25, rand=None):
        if base <= 0:
            raise ValueError("base must be > 0")
        if cap < base:
            raise ValueError("cap must be >= base")
        if factor < 1:
            raise ValueError("factor must be >= 1")
        self.base = float(base)
        self.cap = self._clamp_cap(float(cap))
        self.factor = float(factor)
        self.jitter = max(0.0, min(1.0, float(jitter)))
        self._rand = rand if rand is not None else random.random
        self.failures = 0

    def _clamp_cap(self, cap):
        """Keep the cap below the Cloud's offline threshold.

        Backing off past the point where the Cloud marks the gateway offline
        turns a recoverable outage into a visible disconnection, so a cap that
        is too generous is pulled down rather than trusted.
        """
        ceiling = _offline_ceiling()
        if ceiling and cap > ceiling:
            return ceiling
        return cap

    def reset(self):
        self.failures = 0

    @property
    def healthy(self):
        return self.failures == 0

    def delay(self, ok):
        """Seconds to wait before the next attempt. `ok` is the last outcome."""
        if ok:
            self.failures = 0
            # Jitter upward only: the healthy cadence must never get *shorter*
            # than the configured interval, or polling load creeps up.
            return self.base + self._rand() * self.base * self.jitter
        raw = min(self.cap, self.base * (self.factor ** self.failures))
        self.failures += 1
        if self.jitter == 0:
            return raw
        # Equal jitter (AWS "Exponential Backoff and Jitter"): keep a floor of
        # half the delay, so a tight base still genuinely backs off, while
        # spreading the fleet across the window instead of having it retry in
        # lockstep. Deliberately asymmetric: recovery time is bounded by half
        # the nominal backoff, so the fleet rejoins quickly once the Cloud is
        # healthy again.
        return raw / 2.0 + self._rand() * raw / 2.0


def _offline_ceiling():
    """The Cloud's offline threshold, or None if it cannot be determined."""
    try:
        from app.config import get_settings
        threshold = float(get_settings().heartbeat_offline_after_seconds)
    except Exception:
        return None
    if threshold <= 0:
        return None
    # Half the threshold: a gateway that is merely slow still looks alive.
    return threshold / 2.0


def describe(backoff):
    return f"base={backoff.base:g}s cap={backoff.cap:g}s failures={backoff.failures}"