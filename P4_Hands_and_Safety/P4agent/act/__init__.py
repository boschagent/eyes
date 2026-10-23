"""Hands & Safety (P4): runbook allowlist, approval gate, kill switch, Action API client, verify+rollback."""


def selftest_all() -> None:
    """Run every deterministic test in this package (P1 can call this from agent.selftest)."""
    from agent.act import action_api, approval, killswitch, verify
    for m in (killswitch, approval, action_api, verify):
        m.selftest()
