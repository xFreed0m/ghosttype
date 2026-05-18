"""False-positive-reduction coverage for ghosttype.patterns.

These exercise `_is_likely_placeholder`, the entropy floor, and the
regex/heuristic dedup paths — the logic that keeps a credential scanner from
drowning operators in noise. Each test asserts the actual filtering outcome.
"""
from __future__ import annotations

from ghosttype.patterns import (
    _is_likely_placeholder,
    _shannon_entropy,
    scan_text,
)


def test_shannon_entropy_of_empty_string_is_zero():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_orders_random_above_repetitive():
    assert _shannon_entropy("aaaaaaaa") < _shannon_entropy("aB3$xK9q")


def test_placeholder_too_short_is_filtered():
    assert _is_likely_placeholder("abc") is True


def test_placeholder_known_example_value_is_filtered():
    # AWS docs canonical example key
    assert _is_likely_placeholder("AKIAIOSFODNN7EXAMPLE") is True


def test_placeholder_stem_is_filtered():
    assert _is_likely_placeholder("your-api-key") is True


def test_placeholder_exact_token_is_filtered():
    assert _is_likely_placeholder("changeme") is True


def test_html_like_open_tag_is_filtered():
    assert _is_likely_placeholder("<your-token-here>") is True


def test_html_like_close_marker_is_filtered():
    assert _is_likely_placeholder("sometokenvalue/>") is True


def test_placeholder_suffix_here_is_filtered():
    assert _is_likely_placeholder("insert-token-here") is True


def test_low_entropy_value_is_filtered():
    # 8+ chars, not a known example, but near-zero entropy -> not a real secret
    assert _is_likely_placeholder("aaaaaaaaaaaa") is True


def test_high_entropy_realistic_value_is_not_filtered():
    assert _is_likely_placeholder("Xq9$zR2!mK7#vL4@pW1&") is False


def test_regex_layer_dedups_same_type_and_value():
    """The same GitHub PAT twice in one text yields a single regex match."""
    tok = "ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    out = scan_text(f"first {tok} then again {tok}")
    gh = [m for m in out if m.secret_value == tok]
    assert len(gh) == 1


def test_known_example_regex_value_is_skipped_entirely():
    """A canonical docs token must not be reported even though it matches a
    high-confidence regex shape."""
    out = scan_text("token = ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012")
    assert all(
        m.secret_value != "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012" for m in out
    )


def test_heuristic_placeholder_is_filtered_but_real_value_reported():
    """A heuristic var-name signal with a placeholder value is dropped; the
    same signal with a high-entropy value is kept."""
    dropped = scan_text("api_key = your-key-here")
    assert all("your-key-here" != m.secret_value for m in dropped)

    kept = scan_text("api_key = Zx9Q2mK7vL4pW1aB3cD5eF8gH0jR6tY")
    assert any(m.secret_value == "Zx9Q2mK7vL4pW1aB3cD5eF8gH0jR6tY" for m in kept)


def test_heuristic_dedups_value_already_captured_by_regex():
    """If a value is caught by a high-confidence regex, an overlapping
    heuristic must not re-report the same value."""
    tok = "ghp_a1b2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    out = scan_text(f"github_token = {tok}")
    assert len([m for m in out if m.secret_value == tok]) == 1
