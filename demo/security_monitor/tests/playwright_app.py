"""ASGI entrypoint for browser tests: the real gateway app, plus one optional test hook.

PLAYWRIGHT_PREPARE_HOLD_S=<seconds>: every run waits at the launcher's
'before_agent_start' checkpoint (sandbox rules compiled, agent not started) for
up to that long, or until Stop sets the run's cancel event. This gives a browser
time to press Stop during preparation. Nothing else is changed; production code
has no such knob.
"""
from __future__ import annotations

import os

from demo.security_monitor.app.governance import launcher as _launcher

_HOLD_S = float(os.getenv("PLAYWRIGHT_PREPARE_HOLD_S", "0") or 0)

if _HOLD_S > 0:
    _original_init = _launcher.TaskLauncher.__init__

    def _init_with_hold(self, *args, **kwargs):
        _original_init(self, *args, **kwargs)
        self.test_hooks.setdefault("before_agent_start", lambda launcher: launcher.cancel_event.wait(_HOLD_S))

    _launcher.TaskLauncher.__init__ = _init_with_hold

from demo.security_monitor.app.gateway.server import app  # noqa: E402  (after the hook is installed)
