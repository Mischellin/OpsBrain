"""The three P1 findings Codex raised on the v1 base (#2), tested from the outside.

All three are the same shape of mistake: a guard that exists, is documented, and is not applied on one
particular path. Each test below names the path, because "the guard is there" is exactly what the
original code looked like.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from opsbrain.config import Access
from opsbrain.executor import Result
from opsbrain.util import OpsError


# ------------------------------------------------------------------- every tool result is redacted
def test_a_handler_that_forgets_to_sanitize_cannot_leak(ops) -> None:  # type: ignore[no-untyped-def]
    """`call` is the one place every result passes through, so that is where redaction belongs.

    Ansible failure details, k8s event messages and prometheus alert annotations all carry text nobody
    wrote a redaction call for.
    """
    def leaky(_: Any) -> dict[str, Any]:
        return {"detail": "connection failed: token=ghp_" + "a" * 36, "stderr": "password: hunter2"}

    out = ops.call("hosts", {"action": "status"}, leaky)
    text = json.dumps(out)
    assert "ghp_" not in text, "a raw credential reached the client through an unsanitised handler"
    assert "hunter2" not in text


def test_redaction_keeps_valid_json(ops) -> None:  # type: ignore[no-untyped-def]
    """Structure-aware redaction: the answer must still parse, or the client breaks instead of reading."""
    out = ops.call("hosts", {"action": "status"},
                   lambda: {"total": 2, "hosts": {"web-1": {"ok": True, "note": "password: hunter2"}}})
    # Parsed, not re-encoded. `json.dumps` over an answer that is *already* a JSON string just wraps that
    # string in quotes, so the assertion passed on any output at all - including a corrupted one.
    body = json.loads(out if isinstance(out, str) else out)
    assert body["hosts"]["web-1"]["ok"] is True, "the document survived redaction intact"
    assert body["total"] == 2
    assert "hunter2" not in out, "and the credential did not"


# --------------------------------------------------- hosts.read policy applies to every selected host
def test_a_targeted_hosts_read_denial_blocks_a_batch(ops) -> None:  # type: ignore[no-untyped-def]
    """`hosts.read:pve: deny` was configured and the host was read anyway.

    `ping` and `status` asked about the bare capability and then freely selected hosts, so a targeted rule
    never participated in the decision.
    """
    ops.require = _policy(ops, {"hosts.read:pve": Access.DENY})
    for action in (ops.hosts_ping, ops.hosts_status):
        with pytest.raises(OpsError, match="pve"):
            action()
        with pytest.raises(OpsError, match="pve"):
            action(hosts=["pve"])


def test_a_tag_batch_respects_a_targeted_denial(ops) -> None:  # type: ignore[no-untyped-def]
    ops.require = _policy(ops, {"hosts.read:ops": Access.DENY})
    with pytest.raises(OpsError, match="ops"):
        ops.hosts_ping(hosts=["ops"])


def test_an_allowed_host_still_reads_under_the_same_policy(ops) -> None:  # type: ignore[no-untyped-def]
    ops.require = _policy(ops, {"hosts.read:ops": Access.DENY})
    ops.exec.rules.clear()
    ops.exec.on(r"true", "")
    answer = ops.hosts_ping(hosts=["pve"])
    assert answer["total"] == 1


def test_listing_the_inventory_respects_hosts_read(ops) -> None:  # type: ignore[no-untyped-def]
    """`hosts_list` never called `require` at all, and it returns addresses, jump chains and tags."""
    ops.require = _policy(ops, {"hosts.read": Access.DENY})
    with pytest.raises(OpsError, match="hosts.read"):
        ops.hosts_list()


# ------------------------------------------- an all-namespace k8s read needs every namespace allowed
def test_an_all_namespace_read_is_refused_when_a_namespace_is_denied(ops) -> None:  # type: ignore[no-untyped-def]
    """`-A` returns objects from namespaces the policy denies, and checking the empty target never sees that."""
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [{"metadata": {"name": "prod"}},
                                                        {"metadata": {"name": "kube-system"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.DENY})
    with pytest.raises(OpsError, match="not covered by policy") as raised:
        ops.k8s_get(kind="pods")
    # The refusal says how many namespaces are withheld, never which: naming the target would disclose it
    # by the back door the namespace-listing branch exists to close.
    assert "prod" not in str(raised.value)
    assert "1 namespace(s)" in str(raised.value)


def test_an_all_namespace_read_is_allowed_when_every_namespace_is(ops) -> None:  # type: ignore[no-untyped-def]
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [{"metadata": {"name": "prod"}}]}) + "\n")
    ops.exec.on(r"get pods", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.ALLOW})
    assert ops.k8s_get(kind="pods")["kind"] == "pods"


def test_a_namespaced_read_is_unaffected_by_the_all_namespace_rule(ops) -> None:  # type: ignore[no-untyped-def]
    """Only the cluster-wide path needs every namespace; a normal read must not list them all."""
    ops.exec.rules.clear()
    ops.exec.on(r"get pods", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read:prod": Access.ALLOW})
    assert ops.k8s_get(kind="pods", namespace="prod")["kind"] == "pods"
    assert not any("get namespaces" in script for _, script in ops.exec.calls)


def _policy(ops: Any, rules: dict[str, Access]) -> Any:
    """A `require` bound to these rules, keeping the real error text."""
    from opsbrain.policy import decide

    def require(capability: str, target: str = "") -> None:
        access = decide(rules, capability, target)
        if access is Access.DENY:
            raise OpsError(f"{capability}{':' + target if target else ''} is denied by policy")

    return require


def test_budget_telemetry_is_not_treated_as_a_credential(ops) -> None:  # type: ignore[no-untyped-def]
    """`token` in a budget report is a count, and masking it replaces a number with a string.

    That breaks every client that reports usage and hides the field the operator is actually watching.
    The redaction allowlist is a list of names, not a rule - so it also has to keep masking things that
    merely look like accounting, which is what the neighbour test covers. Either half alone would pass
    against a fix that had simply deleted the masking.
    """
    answer = ops.call("autonomy", {"action": "status"},
                      lambda: {"budget": {"input_tokens": 1200, "output_tokens": 340, "spend_usd": 0.04}})
    budget = json.loads(answer if isinstance(answer, str) else json.dumps(answer))["budget"]
    assert budget["input_tokens"] == 1200 and isinstance(budget["input_tokens"], int)
    assert budget["output_tokens"] == 340
    assert budget["spend_usd"] == 0.04


def test_a_real_credential_still_goes_under_an_accounting_looking_name(ops) -> None:  # type: ignore[no-untyped-def]
    from opsbrain.redact import redact_obj

    masked = redact_obj({"api_key": "sk-live-1", "input_tokens": 7, "nested": {"auth_token": "ghp_" + "x" * 36}})
    assert masked["api_key"] != "sk-live-1"
    assert masked["input_tokens"] == 7
    assert masked["nested"]["auth_token"] != "ghp_" + "x" * 36


def test_a_denied_caller_never_causes_a_cluster_read(ops) -> None:  # type: ignore[no-untyped-def]
    """`require` has to come before the namespace listing, not after it.

    Checking afterwards still means a caller the policy denies already made `kubectl get namespaces` run.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.DENY})
    with pytest.raises(OpsError, match="k8s.read"):
        ops.k8s_get(kind="pods")
    assert not ops.exec.calls, "the cluster was read by a caller the policy denies"


def test_a_cluster_wide_read_names_each_namespace_it_covers(ops) -> None:  # type: ignore[no-untyped-def]
    """Authorising a list and then issuing one `-A` read is not the same as authorising each namespace.

    A namespace created between the two is absent from the authorisation loop and its objects still come
    back in the answer. So the namespaces that were authorised are the namespaces that get read, by name.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    namespaces = {"items": [{"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}}]}
    ops.exec.on(r"get namespaces", json.dumps(namespaces) + "\n")
    for scope in ("default", "prod"):
        ops.exec.on(rf"-n {scope}",
                    json.dumps({"items": [{"metadata": {"name": f"pod-{scope}"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})

    out = ops.k8s_get(kind="pods")
    assert out["namespaces"] == ["default", "prod"]
    scripts = [script for _, script in ops.exec.calls if "get pods" in script]
    assert all("-A" not in script for script in scripts), "no cluster-wide read was issued"
    assert {script.split("-n ")[1].split()[0] for script in scripts} == {"default", "prod"}


def test_a_pass_field_is_not_mistaken_for_a_password(ops) -> None:  # type: ignore[no-untyped-def]
    """`pass` is the tail of `is_pass` and `passed`, and neither is a credential.

    Redacting a boolean because its name contains a substring left `verify_evidence` unreadable: a client
    could not tell whether the check succeeded.
    """
    from opsbrain.redact import redact_obj

    masked = redact_obj({"is_pass": True, "passed": 3, "bypass": False,
                         "api_key": "sk-live-1", "password": "hunter2"})
    assert masked["is_pass"] is True
    assert masked["passed"] == 3
    assert masked["bypass"] is False
    assert masked["api_key"] != "sk-live-1"
    assert masked["password"] != "hunter2", "a key that is only `pass` is still a password"


def test_verification_answers_survive_result_redaction(ops) -> None:  # type: ignore[no-untyped-def]
    """The failure this caused was invisible at the tool boundary, so it is asserted there."""
    ops.exec.rules.clear()
    answer = ops.call("autonomy", {"action": "verify_evidence", "id": "ev-0000abcd"},
                      lambda: {"status": "PASS", "is_pass": True, "passed": 2, "api_key": "sk-live-9"})
    body = json.loads(answer if isinstance(answer, str) else json.dumps(answer))
    assert body["is_pass"] is True
    assert body["passed"] == 2
    assert body["api_key"] != "sk-live-9", "the credential is still redacted"


def test_camel_case_credentials_are_masked_like_their_snake_case_twin(ops) -> None:  # type: ignore[no-untyped-def]
    """Case-folding before looking for separators destroyed the camel-case half.

    `accessToken` folded to `accesstoken` and matched nothing, and an opaque credential under it evades
    the format-specific string patterns, so `Core.call` returned it unchanged.
    """
    from opsbrain.redact import _is_sensitive_key

    for camel, snake in (("accessToken", "access_token"), ("authToken", "auth_token"),
                         ("clientSecret", "client_secret"), ("dbPassword", "db_password"),
                         ("privateKey", "private_key"), ("refreshToken", "refresh_token")):
        assert _is_sensitive_key(camel), f"{camel} names a credential"
        assert _is_sensitive_key(camel) == _is_sensitive_key(snake), "camel and snake are one word"

    answer = ops.call("k8s", {"action": "get"}, lambda: {"accessToken": "opaque-credential-value",
                                                         "isPass": True, "accessLevel": "admin"})
    body = json.loads(answer if isinstance(answer, str) else json.dumps(answer))
    assert body["accessToken"] != "opaque-credential-value", "the credential is masked"
    assert body["isPass"] is True, "a non-secret camel-case neighbour is not collateral damage"
    assert body["accessLevel"] == "admin"

    # The same key already squashed, as an upstream payload that emits `accesstoken` would. There is no
    # separator left in it to be found, and an opaque credential evades the value-pattern checks.
    squashed = ops.call("k8s", {"action": "get"},
                        lambda: {"accesstoken": "opaque-credential-value", "refreshtoken": "another-one",
                                 "tokenizer": "nltk-english", "secretary": "ops"})
    body = json.loads(squashed if isinstance(squashed, str) else squashed)
    assert body["accesstoken"] != "opaque-credential-value", "a squashed credential name is still a name"
    assert body["refreshtoken"] != "another-one"
    assert body["tokenizer"] == "nltk-english", "and the suffix rule does not take ordinary words with it"
    assert body["secretary"] == "ops"


def test_a_stored_full_result_is_still_parseable_json(ops) -> None:  # type: ignore[no-untyped-def]
    """The text redactor does not recognise a quoted marker as done and unquotes it.

    The artifact the truncated response points at was advertised as the full result, and stopped parsing
    the moment it contained a masked field.
    """
    payload = {"rows": list(range(400)), "password": "hunter2", "note": "x" * 400}
    # Shrink the limit so the truncation path - the one that stores an artifact - is the one under test.
    ops.config = ops.config.model_copy(update={
        "limits": ops.config.limits.model_copy(update={"max_chars": 200})})
    answer = ops.call("k8s", {"action": "get"}, lambda: payload)
    body = json.loads(answer if isinstance(answer, str) else json.dumps(answer))
    assert body["truncated"] is True and "artifact" in body

    # Read the file, not `ArtifactStore.read`: that one clips each line for display, which is a different
    # question from whether what was stored still parses.
    stored = (ops.artifacts.root / f"{body['artifact']}.txt").read_text(encoding="utf-8")
    parsed = json.loads(stored)  # the defect: this used to fail on the unquoted marker
    assert parsed["password"] != "hunter2", "the credential is masked in the artifact too"
    assert len(parsed["rows"]) == 400, "and the rest of the document survived"


def test_a_wide_cluster_read_does_not_become_a_serial_queue(ops) -> None:  # type: ignore[no-untyped-def]
    """Authorising per namespace must not turn one request into N sequential subprocesses.

    On a cluster with a hundred namespaces that is a hundred round trips, each waiting on the API, and an
    ordinary MCP call times out while the server is still being loaded.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    count = 24
    names = [{"metadata": {"name": f"ns{i:02d}"}} for i in range(count)]
    ops.exec.on(r"get namespaces", json.dumps({"items": names}) + "\n")
    ops.exec.on(r"get pods", json.dumps({"items": [{"metadata": {"name": "p"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})

    out = ops.k8s_get(kind="pods")
    assert len(out["namespaces"]) == count
    scripts = [script for _, script in ops.exec.calls if "get pods" in script]
    assert len(scripts) == count, "one read per authorised namespace, none skipped"
    assert all("-A" not in script for script in scripts)

    # Bounded, not serial: with a bound of 8 the 24 reads cannot have all started one after another.
    from opsbrain.readers import _K8S_READ_PARALLELISM

    assert 1 < _K8S_READ_PARALLELISM < count, "the bound is what makes this not a queue"


def test_a_denied_namespace_is_not_named_by_the_namespace_listing(ops) -> None:  # type: ignore[no-untyped-def]
    """The listing *is* the disclosure, and namespaces are not themselves namespaced.

    That path never reached the per-namespace check, so `k8s.read:prod: deny` produced a listing that
    named prod - the enforcement the rest of this class exists for, bypassed through a supported call.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [
        {"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}},
        {"metadata": {"name": "staging"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW, "k8s.read:prod": Access.DENY})

    out = ops.k8s_get(kind="namespaces")
    named = [row["name"] for row in out["items"]]
    assert "prod" not in named, "a namespace the policy does not cover is not named"
    assert set(named) == {"default", "staging"}
    # A count, not the names: the whole point of the rule is that `prod` is not disclosed anywhere in the
    # answer, and echoing it back under `withheld` undid that.
    assert out["withheld"] == 1
    assert "prod" not in json.dumps(out), "and the denied name appears nowhere in the response"


def test_a_redaction_marker_survives_a_second_pass(ops) -> None:  # type: ignore[no-untyped-def]
    """Stored text is redacted again on read, and the marker has to be recognised as done.

    Bypassing only the save path left the same corruption on `artifact action=read` and `grep`: the quoted
    marker came back as a bare unquoted token and the document stopped being JSON.
    """
    from opsbrain.redact import redact_obj, redact_text

    once = redact_obj({"password": "hunter2", "rows": [1, 2, 3]})
    assert once["password"] == "[REDACTED:value]"
    twice = redact_obj(once)
    assert twice["password"] == "[REDACTED:value]", "redacting redacted JSON is a no-op"
    json.dumps(twice)  # and the document is still valid JSON

    as_text = json.dumps(once)
    assert redact_text(as_text) == as_text, "a second pass over redacted JSON changes nothing at all"
    assert json.loads(redact_text(as_text))["password"] == "[REDACTED:value]"


def test_the_namespace_listing_is_gated_before_it_reads_the_cluster(ops) -> None:  # type: ignore[no-untyped-def]
    """This branch issues `get namespaces` itself, so the bare capability is checked before it.

    Checking the per-namespace rules only afterwards meant a caller denied `k8s.read` outright had already
    caused the forbidden cluster read - the same mistake the per-namespace fix was made for.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.DENY})
    with pytest.raises(OpsError, match="k8s.read"):
        ops.k8s_get(kind="namespaces")
    assert not ops.exec.calls, "the cluster was read by a caller the policy denies"


def test_a_named_namespace_lookup_is_not_turned_into_a_full_listing(ops) -> None:  # type: ignore[no-untyped-def]
    """`kind="namespaces", name="prod"` is a single-object lookup and must stay one."""
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces prod", json.dumps(
        {"items": [{"metadata": {"name": "prod"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})
    out = ops.k8s_get(kind="namespaces", name="prod")
    scripts = [script for _, script in ops.exec.calls if "get namespaces" in script]
    assert scripts, "the lookup ran"
    assert all("get namespaces prod" in script for script in scripts), "and it asked for the named object"
    assert "namespaces" in out.get("items", [{}])[0] or out.get("kind") == "namespaces"


def test_a_named_object_absent_from_a_namespace_does_not_abort_the_whole_read(ops) -> None:  # type: ignore[no-untyped-def]
    """`kubectl get pods web -n x` exits NotFound unless told to ignore missing objects.

    A named object normally lives in one namespace, so the first namespace without it used to fail the
    entire read - turning a lookup that used to work with `-A` into one that failed on ordinary input.
    """
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [
        {"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}}]}) + "\n")
    ops.exec.on(r"-n default", json.dumps({"items": [{"metadata": {"name": "web"}}]}) + "\n")
    # Exactly what kubectl does: NotFound without the flag, an empty list with it.
    ops.exec.on(r"-n prod", lambda script: (  # type: ignore[arg-type]
        Result(1, 'Error from server (NotFound): pods "web" not found\n')
        if "--ignore-not-found" not in script
        else Result(0, json.dumps({"items": []}) + "\n")))
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})
    out = ops.k8s_get(kind="pods", name="web")
    scripts = [script for _, script in ops.exec.calls if "get pods web" in script]
    assert scripts and all("--ignore-not-found" in script for script in scripts), (
        "a namespace that does not have the object must not end the read")
    assert "web" in json.dumps(out["items"]), "and the namespace that has the object is still reported"
    assert len(out["namespaces"]) == 2, "both authorised namespaces were read"


def test_every_marker_kind_this_module_emits_survives_a_second_pass() -> None:
    """`MARK` emits kinds with underscores - `private_key`, `github_token`, `ansible_vault`."""
    from opsbrain.redact import redact_obj, redact_text

    for kind in ("value", "private_key", "github_token", "ansible_vault"):
        stored = f'{{"api_key": "[REDACTED:{kind}]"}}'
        assert redact_text(stored) == stored, f"a {kind} marker was rewritten on the second pass"
        json.loads(redact_text(stored))
    assert redact_obj({"input_tokens": 7})["input_tokens"] == 7


def test_a_namespace_listing_honours_the_selector_it_was_given(ops) -> None:  # type: ignore[no-untyped-def]
    """The selector was validated and then dropped, so the branch answered with every namespace."""
    from opsbrain.config import Access

    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [
        {"metadata": {"name": "default"}}, {"metadata": {"name": "prod"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})

    ops.k8s_get(kind="namespaces", selector="env=prod")
    scripts = [script for _, script in ops.exec.calls if "get namespaces" in script]
    assert scripts and all("-l env=prod" in script for script in scripts), (
        "the selector was accepted and then not used")


# ------------------------------------------------------- round 2: the same guard, on the paths it missed
def _cluster(ops: Any, *, denied: str = "prod") -> None:
    """A three-namespace cluster where the policy allows k8s.read but denies one namespace."""
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [
        {"metadata": {"name": "default"}}, {"metadata": {"name": denied}},
        {"metadata": {"name": "argocd"}}]}) + "\n")
    ops.exec.on(r"get nodes", json.dumps({"items": []}) + "\n")
    for scope in ("default", denied, "argocd"):
        ops.exec.on(rf"get pods -n {scope}\b",
                    json.dumps({"items": [{"metadata": {"name": f"pod-{scope}", "namespace": scope},
                                           "status": {"phase": "Running", "containerStatuses": []}}]}) + "\n")
        ops.exec.on(rf"get events -n {scope}\b", json.dumps({"items": [
            {"type": "Warning", "reason": f"Failed-{scope}", "message": f"event in {scope}",
             "involvedObject": {"kind": "Pod", "name": f"pod-{scope}"},
             "metadata": {"namespace": scope}, "count": 1}]}) + "\n")


def test_overview_never_reads_a_denied_namespace(ops) -> None:  # type: ignore[no-untyped-def]
    """`k8s_overview` ran `get pods -A` after checking only the bare capability.

    Only `k8s_get` had learned the per-namespace rule, so the overview of a cluster whose policy denies
    `prod` still counted - and named - everything running there.
    """
    _cluster(ops)
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW, "k8s.read:prod": Access.DENY})
    out = ops.k8s_overview()
    scripts = [script for _, script in ops.exec.calls]
    assert all("-A" not in script for script in scripts), "no cluster-wide read was issued"
    assert not any("-n prod" in script for script in scripts), "the denied namespace was never read"
    assert out["pods"]["total"] == 2, "default and argocd were counted, prod was not"
    assert "withheld" in out["pods"]
    assert "prod" not in json.dumps(out), "and the denied name appears nowhere in the answer"


def test_overview_does_not_read_a_denied_argocd_namespace(ops) -> None:  # type: ignore[no-untyped-def]
    """The Argo CD lookup named its namespace in the command and never asked the policy about it."""
    _cluster(ops)
    ops.exec.on(r"get applications\.argoproj\.io -n argocd", json.dumps({"items": []}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW, "k8s.read:argocd": Access.DENY})
    out = ops.k8s_overview()
    assert out["argo"] == "unavailable"
    assert not any("applications" in script for _, script in ops.exec.calls), (
        "the applications of a namespace the policy denies were requested")


def test_events_never_read_a_denied_namespace(ops) -> None:  # type: ignore[no-untyped-def]
    """`k8s_events()` with no namespace ran `get events -A`, carrying event text from every namespace."""
    _cluster(ops)
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW, "k8s.read:prod": Access.DENY})
    out = ops.k8s_events(None)
    scripts = [script for _, script in ops.exec.calls]
    assert all("-A" not in script for script in scripts)
    assert not any("-n prod" in script for script in scripts)
    text = json.dumps(out)
    assert "event in prod" not in text and "Failed-prod" not in text
    assert "event in default" in text, "the namespaces the policy covers are still reported"
    assert "withheld" in out

    # A namespace named explicitly is still judged against its own rule.
    with pytest.raises(OpsError, match="prod"):
        ops.k8s_events("prod")


def test_the_inventory_lists_only_hosts_the_policy_covers(ops) -> None:  # type: ignore[no-untyped-def]
    """`hosts_list` asked about the bare capability, so `hosts.read:pve: deny` never took part.

    The inventory carries the address, the jump chain, the tags and the services of every host.
    """
    ops.require = _policy(ops, {"hosts.read": Access.ALLOW, "hosts.read:pve": Access.DENY})
    out = ops.hosts_list()
    names = {row["name"] for row in out["hosts"]}
    assert "pve" not in names and {"ops", "router"} <= names
    assert out["withheld"] == 1, "a count, never the name"
    assert "10.0.0.11" not in json.dumps(out), "and the denied host's address is not disclosed"


def test_a_named_namespace_is_judged_against_its_own_rule(ops) -> None:  # type: ignore[no-untyped-def]
    """The listing branch was guarded; the lookup by name fell through to the bare capability.

    `kind=namespaces, name=prod` therefore returned the very object `k8s.read:prod: deny` withholds.
    `describe` had the same shape, and so did passing the namespace as `namespace` with no name, which
    kubectl answers by listing every namespace because they are cluster-scoped.
    """
    _cluster(ops)
    ops.exec.on(r"get namespaces prod", json.dumps({"items": [{"metadata": {"name": "prod"}}]}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW, "k8s.read:prod": Access.DENY})

    with pytest.raises(OpsError, match="prod"):
        ops.k8s_get(kind="namespaces", name="prod")
    with pytest.raises(OpsError, match="prod"):
        ops.k8s_describe(kind="namespaces", name="prod")
    assert not any("get namespaces prod" in script or "describe namespace" in script
                   for _, script in ops.exec.calls), "the denied lookup never reached kubectl"

    out = ops.k8s_get(kind="namespaces", namespace="prod")
    assert "prod" not in json.dumps(out.get("namespaces", [])) + json.dumps(out.get("items", []))
    assert out.get("withheld") == 1

    allowed = ops.k8s_get(kind="namespaces", name="default")
    assert allowed["kind"] == "namespaces", "a namespace the policy covers is still readable by name"


def test_a_named_lookup_survives_an_empty_not_found_answer(ops) -> None:  # type: ignore[no-untyped-def]
    """`kubectl get <kind> <name> --ignore-not-found -o json` prints nothing when the object is absent.

    The empty answer is a success, and treating it as malformed JSON ended the whole cluster-wide lookup at
    the first namespace that simply did not have the object.
    """
    ops.exec.rules.clear()
    ops.exec.on(r"get namespaces", json.dumps({"items": [
        {"metadata": {"name": "default"}}, {"metadata": {"name": "web"}}]}) + "\n")
    ops.exec.on(r"-n default", Result(0, ""))
    ops.exec.on(r"-n web", json.dumps({"metadata": {"name": "api", "namespace": "web"}}) + "\n")
    ops.require = _policy(ops, {"k8s.read": Access.ALLOW})
    out = ops.k8s_get(kind="pods", name="api")
    assert out["namespaces"] == ["default", "web"]
    assert "api" in json.dumps(out["items"]), "the namespace that has the object is still reported"


def test_camel_case_pre_shared_keys_are_credentials() -> None:
    """The normaliser puts a separator between `pre` and `shared`, which the patterns did not know."""
    from opsbrain.redact import _is_sensitive_key, redact_obj

    for key in ("preSharedKey", "pre_shared_key", "pre-shared-key", "presharedkey", "PreSharedKey"):
        assert _is_sensitive_key(key), f"{key} names a credential"
        assert redact_obj({key: "opaque-wireguard-value"})[key] != "opaque-wireguard-value"


def test_telemetry_is_exempt_by_value_type_not_by_name() -> None:
    """`tokens` is also what a credential collection is called.

    Exempting the *name* meant `{"tokens": ["opaque-auth-token"]}` passed through unchanged. The exemption
    is for numbers: the thing a budget report actually holds.
    """
    from opsbrain.redact import redact_obj

    kept = redact_obj({"tokens": 12, "input_tokens": 7, "token_budget": 5000.5, "max_tokens": 10,
                       "spend_usd": 0.04})
    assert kept == {"tokens": 12, "input_tokens": 7, "token_budget": 5000.5, "max_tokens": 10,
                    "spend_usd": 0.04}, "numeric accounting survives"

    for key, value in (("tokens", ["opaque-auth-token"]), ("token_budget", "opaque-auth-token"),
                       ("input_tokens", "opaque-auth-token"), ("tokens", {"ci": "opaque-auth-token"}),
                       ("tokens", True)):
        masked = redact_obj({key: value})[key]
        assert masked != value and "opaque-auth-token" not in json.dumps(masked), (
            f"{key}={value!r} is not a number and must be masked")

    # The verification vocabulary is exempt for flags and counts, and for nothing else.
    assert redact_obj({"is_pass": True, "passed": 3, "bypass": False}) == {
        "is_pass": True, "passed": 3, "bypass": False}
    assert redact_obj({"password_changed": "hunter2-opaque"})["password_changed"] != "hunter2-opaque"
