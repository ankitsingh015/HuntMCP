import io
import json
import time

import pytest

import rce_confirm


class _FakeTTY(io.StringIO):
    """A stdin stand-in that reports itself as a real interactive terminal
    -- the one thing an agent's own Bash tool call can never do, which is
    exactly the property request_confirmation() gates on."""

    def isatty(self):
        return True


@pytest.fixture
def token_path(tmp_path):
    return str(tmp_path / "os-shell-confirm.json")


def test_request_confirmation_refuses_when_stdin_is_not_a_tty(token_path):
    """Core guarantee: an automated caller (an agent's Bash tool call is
    never interactive) cannot self-confirm just by piping the right text in
    -- only a real terminal counts."""
    stdin = io.StringIO("example.com\n")  # plain StringIO: isatty() is False
    ok = rce_confirm.request_confirmation(
        "example.com", stdin=stdin, stdout=io.StringIO(), path=token_path
    )
    assert ok is False
    assert not rce_confirm._token_exists(token_path)


def test_request_confirmation_writes_a_token_on_a_real_tty_with_matching_text(token_path):
    stdin = _FakeTTY("example.com\n")
    ok = rce_confirm.request_confirmation(
        "example.com", stdin=stdin, stdout=io.StringIO(), path=token_path
    )
    assert ok is True
    with open(token_path) as f:
        token = json.load(f)
    assert token["target"] == "example.com"
    assert token["consumed"] is False


def test_request_confirmation_declines_on_mismatched_text(token_path):
    stdin = _FakeTTY("not-the-target.com\n")
    ok = rce_confirm.request_confirmation(
        "example.com", stdin=stdin, stdout=io.StringIO(), path=token_path
    )
    assert ok is False
    assert not rce_confirm._token_exists(token_path)


def test_check_and_consume_true_once_for_a_fresh_token(token_path):
    rce_confirm.request_confirmation(
        "example.com", stdin=_FakeTTY("example.com\n"), stdout=io.StringIO(), path=token_path
    )
    assert rce_confirm.check_and_consume("example.com", path=token_path) is True


def test_check_and_consume_is_single_use(token_path):
    """The second --os-shell attempt must need its OWN fresh human confirm
    -- one confirmation must not silently authorize an unbounded run of
    persistent-RCE commands."""
    rce_confirm.request_confirmation(
        "example.com", stdin=_FakeTTY("example.com\n"), stdout=io.StringIO(), path=token_path
    )
    assert rce_confirm.check_and_consume("example.com", path=token_path) is True
    assert rce_confirm.check_and_consume("example.com", path=token_path) is False


def test_check_and_consume_false_with_no_token_file(token_path):
    assert rce_confirm.check_and_consume("example.com", path=token_path) is False


def test_check_and_consume_false_once_expired(token_path):
    rce_confirm.request_confirmation(
        "example.com",
        ttl_seconds=-1,  # already expired the instant it's written
        stdin=_FakeTTY("example.com\n"),
        stdout=io.StringIO(),
        path=token_path,
    )
    assert rce_confirm.check_and_consume("example.com", path=token_path) is False


def test_check_and_consume_false_on_malformed_token_file(token_path):
    with open(token_path, "w") as f:
        f.write("not valid json{{{")
    assert rce_confirm.check_and_consume("example.com", path=token_path) is False


def test_check_and_consume_false_when_target_does_not_match_the_token(token_path):
    """Regression (code-review finding, CONFIRMED, corroborated by 5
    independent review angles): the token must be bound to the target it
    was confirmed for. A human confirming '--os-shell' against target-a.com
    must not silently authorize the same action against a different
    target-b.com just because a fresh, unexpired token happens to exist."""
    rce_confirm.request_confirmation(
        "target-a.com", stdin=_FakeTTY("target-a.com\n"), stdout=io.StringIO(), path=token_path
    )
    assert rce_confirm.check_and_consume("target-b.com", path=token_path) is False
    # And the mismatched attempt must NOT have burned the token -- the
    # correct target can still redeem it afterwards.
    assert rce_confirm.check_and_consume("target-a.com", path=token_path) is True
