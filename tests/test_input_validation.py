"""Boundary validation at the attack-module dispatch (DataFactor hygiene pass).

``titan/core/scan_params.py`` gives the per-endpoint module boundary a pydantic
schema. These tests pin both directions: valid shapes (including the local-lab
relative-path convention) pass, and malformed inputs raise the typed
``TitanValidationError`` instead of reaching module logic.
"""

import pytest
from pydantic import ValidationError

from titan.core.scan_params import ScanParams, TitanValidationError, validate_scan_params


def _validate(**overrides):
    base = dict(
        target="https://app.example.com",
        method="GET",
        url="/logic_negative_accepted",
        params={"amount": "10"},
    )
    base.update(overrides)
    return validate_scan_params(**base)


class TestValidInputs:
    def test_relative_path_on_target_origin(self):
        model = _validate()
        assert model.params == {"amount": "10"}

    def test_absolute_url_accepted(self):
        model = _validate(url="https://app.example.com/cart")
        assert model.url == "https://app.example.com/cart"

    def test_method_is_normalized_to_uppercase(self):
        assert _validate(method="post").method == "POST"

    def test_numeric_params_coerced_to_strings(self):
        model = _validate(params={"amount": 10, "qty": 2.5})
        assert model.params == {"amount": "10", "qty": "2.5"}

    def test_empty_params_allowed(self):
        assert _validate(params={}).params == {}


class TestRejections:
    def test_empty_target_rejected(self):
        with pytest.raises(TitanValidationError):
            _validate(target="")

    def test_relative_target_rejected(self):
        with pytest.raises(TitanValidationError):
            _validate(target="app.example.com/cart")

    def test_relative_url_rejected(self):
        with pytest.raises(TitanValidationError):
            _validate(url="cart/checkout")

    def test_unknown_method_rejected(self):
        with pytest.raises(TitanValidationError):
            _validate(method="BREW")

    def test_non_string_param_value_rejected(self):
        with pytest.raises(TitanValidationError):
            _validate(params={"amount": ["10"]})

    def test_none_params_treated_as_empty(self):
        assert _validate(params=None).params == {}

    def test_error_is_a_valueerror(self):
        with pytest.raises(ValueError):
            _validate(target="")


class TestSchemaShape:
    def test_model_rejects_unknown_fields(self):
        # extra="forbid" is enforced by the model itself; direct construction
        # raises pydantic's raw ValidationError, while validate_scan_params()
        # wraps every pydantic failure into the typed TitanValidationError.
        with pytest.raises(ValidationError):
            ScanParams(
                target="https://a.example",
                method="GET",
                url="/x",
                params={},
                extra_field="nope",  # type: ignore[call-arg]
            )

    def test_pydantic_model_is_scanparams(self):
        assert isinstance(_validate(), ScanParams)


class TestEnginePipelineSeam:
    async def test_run_logic_rejects_bad_input_before_module_logic(self, monkeypatch):
        """_run_logic validates at the boundary: malformed inputs raise before
        the detector is even constructed; valid inputs reach it unchanged."""
        from titan.core.module_bindings import AttackModuleBindings
        from titan.core.scan_params import TitanValidationError
        import titan.modules.logic.detector as logic_detector_module

        calls = []

        class _StubDetector:
            def __init__(self, smith, fp):
                pass

            async def scan(self, ctx, t, m, u, p):
                calls.append((t, m, u, p))
                return []

        monkeypatch.setattr(logic_detector_module, "LogicDetector", _StubDetector)

        bindings = AttackModuleBindings()
        bindings.engine = type("_Engine", (), {"payload_smith": None})()

        with pytest.raises(TitanValidationError):
            await bindings._run_logic(None, "not-a-target", "GET", "/x", {}, {})
        assert calls == [], "detector must not run when validation fails"

        result = await bindings._run_logic(
            None, "https://app.example.com", "GET", "/x", {"a": "1"}, {}
        )
        assert result == []
        assert calls == [("https://app.example.com", "GET", "/x", {"a": "1"})]
