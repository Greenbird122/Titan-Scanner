#!/usr/bin/env python3
"""
Test the mutation loop coordinator without running actual scans.
Verifies file management, state tracking, and termination logic.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from coordinator import MutationState, check_termination
from pathlib import Path
import tempfile
import shutil

def test_state_management():
    """Test that MutationState creates and manages files correctly."""
    # Create temp directory
    tmpdir = tempfile.mkdtemp()
    try:
        state = MutationState(tmpdir)

        # Check files were created
        assert (Path(tmpdir) / "estate.md").exists(), "estate.md not created"
        assert (Path(tmpdir) / "findings.md").exists(), "findings.md not created"
        assert (Path(tmpdir) / "mutations.md").exists(), "mutations.md not created"
        assert (Path(tmpdir) / "hypotheses.md").exists(), "hypotheses.md not created"
        assert (Path(tmpdir) / "log.md").exists(), "log.md not created"
        assert (Path(tmpdir) / "iteration.json").exists(), "iteration.json not created"

        # Test iteration tracking
        assert state.get_iteration() == 0, "Initial iteration should be 0"
        state.increment_iteration()
        assert state.get_iteration() == 1, "After increment, should be 1"

        # Test read/write
        state.write("findings.md", "# Test Finding\nThis is a test.")
        content = state.read("findings.md")
        assert "Test Finding" in content, "Write/read failed"

        # Test log append
        state.write("log.md", "## Iteration 1")
        state.write("log.md", "## Iteration 2")
        log = state.read("log.md")
        assert "Iteration 1" in log and "Iteration 2" in log, "Log append failed"

        print("[PASS] State management")
        return True
    finally:
        shutil.rmtree(tmpdir)


def test_termination_logic():
    """Test termination conditions."""
    tmpdir = tempfile.mkdtemp()
    try:
        state = MutationState(tmpdir)

        # Write some active hypotheses so it doesn't terminate on empty
        state.write("hypotheses.md", "# Hypotheses\n\n## Active\n- Test SQLi on /api\n- Test XSS on /search\n\n## Exhausted\n")

        # Should not terminate at iteration 0
        should_stop, reason = check_termination(state, max_iterations=10)
        assert not should_stop, f"Should not stop at iteration 0: {reason}"

        # Should terminate at max iterations
        for _ in range(10):
            state.increment_iteration()
        should_stop, reason = check_termination(state, max_iterations=10)
        assert should_stop, f"Should stop at max iterations: {reason}"

        # Should terminate when hypotheses exhausted
        state2 = MutationState(tempfile.mkdtemp())
        state2.write("hypotheses.md", "# Hypotheses\n\n## Active\n\n## Exhausted\n- Tried SQLi\n")
        should_stop, reason = check_termination(state2, max_iterations=10)
        assert should_stop, f"Should stop when no active hypotheses: {reason}"

        print("[PASS] Termination logic")
        return True
    finally:
        shutil.rmtree(tmpdir)


def test_template_loading():
    """Test that templates load correctly."""
    template_dir = Path(__file__).parent / "templates"
    if template_dir.exists():
        for template in template_dir.glob("*.md"):
            content = template.read_text()
            assert len(content) > 0, f"Template {template.name} is empty"
        print("[PASS] Templates")
    else:
        print("[SKIP] Templates directory not found")
    return True


def test_model_config():
    """Test that model configuration is valid."""
    from coordinator import MODELS, CORE_RULES

    assert len(MODELS) == 4, f"Expected 4 models, got {len(MODELS)}"
    assert "scanner" in MODELS, "Missing scanner model"
    assert "mutator" in MODELS, "Missing mutator model"
    assert "verifier" in MODELS, "Missing verifier model"
    assert "researcher" in MODELS, "Missing researcher model"

    assert len(CORE_RULES) > 0, "Core rules are empty"
    assert "Grep every response" in CORE_RULES, "Core rules missing key rule"
    print("[PASS] Model configuration")
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("MUTATION LOOP — TEST SUITE")
    print("=" * 60)

    tests = [
        test_model_config,
        test_template_loading,
        test_state_management,
        test_termination_logic,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'=' * 60}")

    sys.exit(0 if failed == 0 else 1)
