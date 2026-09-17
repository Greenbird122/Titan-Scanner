"""Tests for verdict classification — the non-answer-is-not-a-verdict doctrine.

Scenario fixtures mirror the 2026-09-12/13 Parool engagement, where an
empty-variables probe's VALIDATION-ERROR was counted as a verdict and
coverage was published as 88/93 before being corrected to 87/93.
"""

from titan.verify.verdicts import Verdict, VerdictLedger, classify


class TestClassify:
    def test_validation_error_is_unverdicted_not_negative(self):
        """The core rule: VALIDATION-ERROR means UNVERDICTED, always."""
        body = (
            '{"errors":[{"message":"Variable \\"$id\\" of required type '
            '\'String!\' was not provided.","extensions":{"code":'
            '"GRAPHQL_VALIDATION_FAILED"}}]}'
        )
        assert classify(400, body) is Verdict.UNVERDICTED

    def test_in_envelope_validation_error_is_unverdicted(self):
        """Status 200 with errors[] still not a verdict (Parool flavor)."""
        body = (
            '{"errors":[{"message":"must provide a value for variable $id",'
            '"extensions":{"code":"BAD_USER_INPUT"}}]}'
        )
        assert classify(200, body) is Verdict.UNVERDICTED

    def test_plain_400_with_validation_marker_is_unverdicted(self):
        assert classify(400, "Variable $unique of required type String! was not provided") is Verdict.UNVERDICTED

    def test_gate_statuses_are_verdicts(self):
        assert classify(401, "unauthorized") is Verdict.GATED
        assert classify(403, "forbidden") is Verdict.GATED

    def test_reachable(self):
        assert classify(200, '{"data":{"ok":true}}') is Verdict.REACHABLE
        assert classify(201, None) is Verdict.REACHABLE

    def test_not_found_statuses(self):
        assert classify(404, "nope") is Verdict.NOT_FOUND
        assert classify(405, "method not allowed") is Verdict.NOT_FOUND

    def test_server_errors_and_ambiguity_are_unverdicted(self):
        """A 5xx answers nothing about the operation — never a negative."""
        assert classify(500, "boom") is Verdict.UNVERDICTED
        assert classify(429, "slow down") is Verdict.UNVERDICTED
        assert classify(302, "") is Verdict.UNVERDICTED

    def test_401_with_validation_body_is_unverdicted(self):
        """A gate refusal that carries validation errors is ambiguous —
        the non-answer wins, because the operation never executed."""
        body = '{"errors":[{"message":"Variable $id of required type String! was not provided"}]}'
        assert classify(401, body) is Verdict.UNVERDICTED

    def test_garbage_body_on_400_is_unverdicted(self):
        """A 400 without a recognized marker is ambiguous, not a verdict."""
        assert classify(400, "<html>bad request</html>") is Verdict.UNVERDICTED


class TestVerdictLedger:
    def test_unverdicted_ops_do_not_count_as_coverage(self):
        ledger = VerdictLedger()
        ledger.record("opA", Verdict.REACHABLE)
        ledger.record("opB", Verdict.GATED)
        ledger.record("opC", Verdict.UNVERDICTED)
        verdicted, total = ledger.coverage()
        assert (verdicted, total) == (2, 3)
        assert ledger.unverdicted == ["opC"]

    def test_parool_overcount_regression(self):
        """The historical failure: 88/93 published, really 87 verdicted + 1
        non-answer. The ledger must produce the honest pair."""
        ledger = VerdictLedger()
        for i in range(87):
            ledger.record(f"op{i}", Verdict.GATED)
        ledger.record("GetContactFormUploadLink", Verdict.UNVERDICTED)
        verdicted, total = ledger.coverage(total_registered=93)
        assert verdicted == 87
        assert total == 93
        assert "coverage: 87/93 verdicted" in ledger.summary(total_registered=93)
        assert "1 UNVERDICTED (re-probe)" in ledger.summary(total_registered=93)

    def test_registered_but_never_probed_depresses_coverage(self):
        """A staged script that never ran is not on the board until it has
        a verdict — and its absence must show in the denominator."""
        ledger = VerdictLedger()
        ledger.record("ran_op", Verdict.REACHABLE)
        verdicted, total = ledger.coverage(total_registered=5)
        assert (verdicted, total) == (1, 5)

    def test_total_registered_smaller_than_recorded_raises(self):
        ledger = VerdictLedger()
        ledger.record("a", Verdict.REACHABLE)
        ledger.record("b", Verdict.REACHABLE)
        try:
            ledger.coverage(total_registered=1)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")

    def test_re_record_updates_and_changes_are_logged(self):
        ledger = VerdictLedger()
        ledger.record("op", Verdict.UNVERDICTED)
        ledger.record("op", Verdict.GATED)
        assert ledger.get("op") is Verdict.GATED
        verdicted, total = ledger.coverage()
        assert (verdicted, total) == (1, 1)

    def test_empty_operation_rejected(self):
        try:
            VerdictLedger().record("", Verdict.GATED)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")

    def test_counts_shape(self):
        ledger = VerdictLedger()
        ledger.extend([("a", Verdict.REACHABLE), ("b", Verdict.UNVERDICTED)])
        counts = ledger.counts()
        assert counts["reachable"] == 1
        assert counts["unverdicted"] == 1
        assert counts["gated"] == 0

    def test_operations_listing(self):
        ledger = VerdictLedger()
        ledger.extend([("z", Verdict.GATED), ("a", Verdict.GATED)])
        assert ledger.operations == ["z", "a"]
