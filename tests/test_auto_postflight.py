"""#10 OPS-AUTO-08: postflight asks whether the goal was met, and cannot be talked into saying yes.

The properties under test are the ones that keep an observation from becoming a second authority: the
outcome vocabulary has no member meaning "approve", a missing verification report caps the answer at
`UNCLEAR` before the model is asked anything, and a reviewer that failed did not clear the change.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opsbrain.auto import postflight as module
from opsbrain.auto.config import AutoConfig
from opsbrain.auto.postflight import POSTFLIGHT_RUBRIC, Outcome, Postflight, postflight
from opsbrain.auto.review import ReviewRequest, ReviewResult, RunnerStatus, Subject, Verdict
from opsbrain.auto.service import ReviewService


class ScriptedReviewer:
    """Answers with a fixed verdict, and records what it was shown.

    Recording the context is the point: several of these tests are about what the model does *not* get to
    decide, which cannot be checked from the verdict alone.
    """

    name = "scripted"

    def __init__(self, verdict: Verdict, status: RunnerStatus = RunnerStatus.OK, **fields: Any) -> None:
        self.verdict, self.status, self.fields = verdict, status, fields
        self.seen: list[ReviewRequest] = []

    def review(self, request: ReviewRequest) -> str:
        # A runner answers with the raw JSON document; `ReviewService` owns turning it into a result.
        self.seen.append(request)
        document = {"contract_version": request.contract_version, "review_id": request.review_id,
                    "subject": request.subject.value, "subject_ref": request.subject_ref,
                    "status": self.status.value,
                    "verdict": self.verdict.value if self.verdict else None,
                    "findings": self.fields.get("findings", []),
                    "unverified_claims": [], "next_checks": [], **{
                        k: v for k, v in self.fields.items() if k != "findings"}}
        return json.dumps(document)


def service_for(tmp_path: Path, reviewer: Any) -> ReviewService:
    auto = AutoConfig(enabled=True, review={"runner": "codex"})
    return ReviewService(auto, tmp_path / "auto", reviewer=reviewer)


def passing_report(**overrides: Any) -> dict[str, Any]:
    """A report of the shape `verify_plan` returns, naming the change it is about.

    `change_id` is not decoration: a postflight now refuses a report that does not name the change being
    judged, so a fixture carrying a plausible-but-unrelated id would have been measuring the refusal
    rather than the thing each test is about.
    """
    return {"change_id": "c-1", "status": "PASS", "is_pass": True, "checks": 2,
            "outstanding": [], "evidence_refs": ["ev-aaaaaaaabbbbbbbb"], **overrides}


def test_nothing_measured_cannot_be_confirmed(tmp_path: Path) -> None:
    """Fail-closed, before the model is asked anything.

    A judgement made with no measurements is a guess, and a guess that says "confirmed" is the worst
    possible guess - so the reviewer is not consulted at all.
    """
    reviewer = ScriptedReviewer(Verdict.PASS)
    result = postflight(service_for(tmp_path, reviewer), change_id="c-0000a1b2", plan_id="pl-1",
                        objective="logrotate stops on web-1", post_checks=(), rollback="revert",
                        verification=None)
    assert result.outcome is Outcome.UNCLEAR
    assert not result.confirmed
    assert reviewer.seen == [], "the model was never asked to judge an unmeasured outcome"
    assert "did not run" in result.reason


def test_checks_that_ran_and_failed_are_not_met(tmp_path: Path) -> None:
    reviewer = ScriptedReviewer(Verdict.PASS)
    result = postflight(service_for(tmp_path, reviewer), change_id="c-1", plan_id="pl-1",
                        objective="o", post_checks=("systemctl is-active logrotate.timer",), rollback="r",
                        verification=passing_report(status="FAIL", reason="unit is masked",
                                                    outstanding=[{"check": "systemd:unit-active"}]))
    assert result.outcome is Outcome.NOT_MET
    assert reviewer.seen == [], "a model cannot overturn a check that reported the opposite"
    assert "FAIL" in result.reason


def test_a_pass_reaches_the_model_with_the_goal_and_the_facts(tmp_path: Path) -> None:
    reviewer = ScriptedReviewer(Verdict.PASS, model="test-model")
    result = postflight(service_for(tmp_path, reviewer), change_id="c-1", plan_id="pl-1",
                        objective="logrotate stops on web-1", post_checks=("systemctl is-active logrotate",),
                        rollback="systemctl revert", verification=passing_report())
    assert result.outcome is Outcome.CONFIRMED and result.confirmed
    assert result.review_id and result.model == "test-model"
    shown = reviewer.seen[0]
    assert shown.subject is Subject.INFRA_RESULT
    assert shown.rubric_version == POSTFLIGHT_RUBRIC, "a postflight is not the plan's cached review"
    assert "logrotate stops on web-1" in shown.context
    assert "systemctl revert" in shown.context, "the model is told what undoing would cost"
    assert "authorisation is not yours to give" in shown.context


def test_a_reviewer_that_failed_did_not_clear_the_change(tmp_path: Path) -> None:
    """A model asked to judge an outcome it could not measure will agree with whatever it is shown."""
    reviewer = ScriptedReviewer(Verdict.PASS, status=RunnerStatus.TIMEOUT)
    result = postflight(service_for(tmp_path, reviewer), change_id="c-1", plan_id="pl-1", objective="o",
                        post_checks=(), rollback="", verification=passing_report())
    assert result.outcome is Outcome.UNCLEAR
    assert not result.confirmed
    assert "TIMEOUT" in result.reason


def test_an_unrecognised_verdict_is_never_a_confirmation(tmp_path: Path) -> None:
    reviewer = ScriptedReviewer(Verdict.PASS)
    service = service_for(tmp_path, reviewer)

    class Odd(ReviewService):
        def review(self, request: ReviewRequest) -> ReviewResult:  # type: ignore[override]
            reviewer.seen.append(request)
            return ReviewResult(review_id=request.review_id, subject=request.subject,
                                subject_ref=request.subject_ref, status=RunnerStatus.OK, verdict=Verdict.PASS)

    # A verdict this code has no mapping for must fall through to UNCLEAR, not to a confirmation.
    from opsbrain.auto import postflight as module

    original = module._VERDICT_MAP
    module._VERDICT_MAP = {**original, "PASS": Outcome.NOT_MET}
    try:
        result = module.postflight(service, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
                                   rollback="", verification=passing_report())
        assert result.outcome is Outcome.NOT_MET
    finally:
        module._VERDICT_MAP = original


def test_the_outcome_vocabulary_cannot_authorise() -> None:
    """There is no member meaning "approved", and that is the property, not an oversight."""
    values = {member.value for member in Outcome}
    assert values == {"confirmed", "not_met", "unclear"}
    assert not any("approv" in value or "allow" in value for value in values)


def test_next_action_says_what_to_do_about_it() -> None:
    base = {"change_id": "c-1", "plan_id": "pl-1", "reason": "r"}
    assert "close it" in Postflight(outcome=Outcome.CONFIRMED, **base).next_action()
    assert "roll back" in Postflight(outcome=Outcome.NOT_MET, **base).next_action()
    assert "run the checks" in Postflight(outcome=Outcome.UNCLEAR, **base).next_action()


def test_a_record_round_trips(tmp_path: Path) -> None:
    result = Postflight(change_id="c-1", plan_id="pl-1", outcome=Outcome.NOT_MET, reason="r",
                        findings=("the unit is masked",), evidence_refs=("ev-aaaaaaaabbbbbbbb",))
    document = result.to_dict()
    assert document["id"].startswith("pf")
    assert document["outcome"] == "not_met"
    assert json.loads(json.dumps(document)) == document


def test_a_report_about_another_change_cannot_confirm_this_one(tmp_path: Path) -> None:
    """The report is handed in by the caller, so its identity is the only thing tying it to this change.

    `verify_plan` reports against the plan a caller names and the executor's change is a different id for
    the same object, so both are accepted. A third id is somebody else's facts, and an absent one was
    never measured against anything in particular - neither is a measurement of this change.
    """
    reviewer = ScriptedReviewer(Verdict.PASS)
    service = service_for(tmp_path, reviewer)
    stranger = module.postflight(service, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
                                 rollback="", verification=passing_report(change_id="c-someone-else"))
    assert stranger.outcome is Outcome.UNCLEAR
    assert not reviewer.seen, "the reviewer was asked to judge on somebody else's observations"
    assert "not for c-1" in stranger.reason

    anonymous = module.postflight(service, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
                                  rollback="", verification=passing_report(change_id=""))
    assert anonymous.outcome is Outcome.UNCLEAR

    # The plan id is the same object under its other name, and is accepted.
    assert module.postflight(service, change_id="c-1", plan_id="c-1", objective="o", post_checks=(),
                             rollback="", verification=passing_report()).outcome is Outcome.CONFIRMED


def test_a_pass_that_carries_a_blocker_is_not_a_confirmation(tmp_path: Path) -> None:
    """The review contract says a BLOCKER vetoes a pass, and the postflight has to honour that.

    Mapping the raw verdict here told the operator to close a change on the strength of a response that
    contained its own veto - the one contradiction the rest of the pipeline makes impossible to express.
    """
    from opsbrain.auto.review import Finding

    reviewer = ScriptedReviewer(Verdict.PASS, findings=[{"summary": "the unit is masked",
                                                         "severity": "BLOCKER"}])
    result = module.postflight(service_for(tmp_path, reviewer), change_id="c-1", plan_id="pl-1",
                               objective="o", post_checks=(), rollback="", verification=passing_report())
    assert result.outcome is Outcome.NOT_MET, result.reason
    assert "BLOCKER" in result.reason, result.reason
    assert "the unit is masked" in result.findings, result.findings
    assert Finding is not None


def test_the_postflight_names_the_configured_model_so_its_identity_moves_with_it(tmp_path: Path) -> None:
    """The review id is content-addressed over the model, so an unnamed model is an identity of its own.

    Leaving it at the empty default made every postflight hash the same whatever was configured: switching
    reviewers and re-running reused the previous model's cached verdict, and a runner that omits its model
    left the record unattributed.
    """
    def for_model(root: Path, model: str) -> Any:
        service = service_for(root, ScriptedReviewer(Verdict.PASS))
        # A real `AutoConfig`, not `model_copy(update=...)`: that does not validate, so `review` would be
        # a plain dict - and a test that read a model out of a dict would be testing the reader's
        # tolerance rather than the naming.
        service.config = AutoConfig(enabled=True, review={"runner": "codex", "model": model})
        return service

    first, second = for_model(tmp_path / "a", "gpt-a"), for_model(tmp_path / "b", "gpt-b")
    asked: list[str] = []
    for service in (first, second):
        result = module.postflight(service, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
                                   rollback="", verification=passing_report())
        assert result.outcome is Outcome.CONFIRMED, result.reason
        asked.append(service._reviewer.seen[-1].model)
    assert asked == ["gpt-a", "gpt-b"], asked
    assert module.postflight(first, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
                             rollback="", verification=passing_report()).review_id != module.postflight(
        second, change_id="c-1", plan_id="pl-1", objective="o", post_checks=(),
        rollback="", verification=passing_report()).review_id, (
        "the same goal judged by two models is two reviews, not one cached verdict")
