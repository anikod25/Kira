"""
kira/planner_patch.py
Reference snippets for Day 5 planner wiring.

This file is intentionally non-runtime documentation.
"""

NEW_INIT = """
def __init__(..., logger=None, guard=None):
    self._logger = logger
    self._guard = guard
    self._privesc_engine = None
"""

LOGGER_ACTION_CALL = """
if self._logger:
    self._logger.action(...)
"""

GUARD_CHECK = """
if self._guard is not None:
    allowed, block_reason = self._guard.check_action(action)
"""

PRIVESC_METHOD = """
def _run_privesc_engine(self):
    ...
"""

NEW_ADVANCE_PHASE = """
def _do_advance_phase(self):
    ...
"""
