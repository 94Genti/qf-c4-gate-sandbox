"""Verify PR audit receipts and set an exact-head commit status.

This script is intentionally stdlib-only. In GitHub Actions it runs from the
trusted default-branch workflow and evaluates PR issue comments; it never needs
to check out or execute PR branch code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RECEIPT_START = "<!-- QF-AUDIT-RECEIPT:START -->"
RECEIPT_END = "<!-- QF-AUDIT-RECEIPT:END -->"
RECEIPT_SCHEMA = "qf.audit_receipt.v1"
DEFAULT_CONTEXT = "audit-receipt/head-sha"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ReceiptConfig:
    allowed_issuers: tuple[str, ...]
    allowed_auditors: tuple[str, ...]
    max_age_hours: int = 168
    now: datetime | None = None
    context: str = DEFAULT_CONTEXT


@dataclass(frozen=True)
class GateResult:
    ok: bool
    reason: str
    description: str
    context: str = DEFAULT_CONTEXT
    matching_comment_url: str | None = None

    @property
    def state(self) -> str:
        return "success" if self.ok else "failure"


@dataclass(frozen=True)
class _Candidate:
    payload: dict[str, Any] | None
    issuer: str
    comment_url: str | None
    parse_error: str | None = None


def _split_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _utc_now(config: ReceiptConfig) -> datetime:
    if config.now is None:
        return datetime.now(timezone.utc)
    if config.now.tzinfo is None:
        return config.now.replace(tzinfo=timezone.utc)
    return config.now.astimezone(timezone.utc)


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = f"{raw[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _comment_issuer(comment: dict[str, Any]) -> str:
    user = comment.get("user")
    if isinstance(user, dict) and isinstance(user.get("login"), str):
        return user["login"]
    return ""


def _receipt_segments(body: str) -> tuple[str, ...]:
    segments: list[str] = []
    start_at = 0
    while True:
        start = body.find(RECEIPT_START, start_at)
        if start < 0:
            return tuple(segments)
        json_start = start + len(RECEIPT_START)
        end = body.find(RECEIPT_END, json_start)
        if end < 0:
            segments.append("")
            return tuple(segments)
        segments.append(body[json_start:end].strip())
        start_at = end + len(RECEIPT_END)


def _iter_candidates(comments: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> tuple[_Candidate, ...]:
    candidates: list[_Candidate] = []
    for comment in comments:
        body = comment.get("body")
        if not isinstance(body, str) or RECEIPT_START not in body:
            continue
        issuer = _comment_issuer(comment)
        url = comment.get("html_url") if isinstance(comment.get("html_url"), str) else None
        for segment in _receipt_segments(body):
            if not segment:
                candidates.append(_Candidate(None, issuer, url, "receipt_markers_malformed"))
                continue
            try:
                payload = json.loads(segment)
            except json.JSONDecodeError:
                candidates.append(_Candidate(None, issuer, url, "receipt_json_invalid"))
                continue
            if not isinstance(payload, dict):
                candidates.append(_Candidate(None, issuer, url, "receipt_json_not_object"))
                continue
            candidates.append(_Candidate(payload, issuer, url))
    return tuple(candidates)


def _failure(reason: str, config: ReceiptConfig, *, description: str | None = None) -> GateResult:
    return GateResult(
        ok=False,
        reason=reason,
        description=(description or reason).replace("_", " ")[:140],
        context=config.context,
    )


def _validate_candidate(
    candidate: _Candidate,
    *,
    pr_number: int,
    head_sha: str,
    config: ReceiptConfig,
) -> GateResult:
    if candidate.parse_error:
        return _failure(candidate.parse_error, config)
    payload = candidate.payload
    if payload is None:
        return _failure("receipt_missing", config)
    if candidate.issuer not in config.allowed_issuers:
        return _failure("receipt_issuer_not_allowed", config)
    if payload.get("schema") != RECEIPT_SCHEMA:
        return _failure("receipt_schema_invalid", config)
    if payload.get("verdict") != "PASS":
        return _failure("receipt_verdict_not_pass", config)
    if payload.get("pr") != pr_number:
        return _failure("receipt_pr_mismatch", config)
    receipt_sha = payload.get("head_sha")
    if not isinstance(receipt_sha, str) or not _SHA_RE.fullmatch(receipt_sha):
        return _failure("receipt_head_sha_invalid", config)
    if receipt_sha != head_sha:
        return _failure("receipt_head_sha_mismatch", config)
    auditor = payload.get("auditor")
    if auditor not in config.allowed_auditors:
        return _failure("receipt_auditor_not_allowed", config)
    completed = _parse_utc(payload.get("audit_completed_utc"))
    if completed is None:
        return _failure("receipt_completed_at_invalid", config)
    now = _utc_now(config)
    if completed > now:
        return _failure("receipt_completed_in_future", config)
    age_seconds = (now - completed).total_seconds()
    if age_seconds > config.max_age_hours * 3600:
        return _failure("receipt_expired", config)
    return GateResult(
        ok=True,
        reason="receipt_valid",
        description=f"Audit receipt PASS for {head_sha[:12]}",
        context=config.context,
        matching_comment_url=candidate.comment_url,
    )


def evaluate_receipts(
    *,
    comments: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    pr_number: int,
    head_sha: str,
    config: ReceiptConfig,
) -> GateResult:
    if not _SHA_RE.fullmatch(head_sha):
        return _failure("pr_head_sha_invalid", config)
    candidates = _iter_candidates(comments)
    if not candidates:
        return _failure("receipt_missing", config)

    first_failure: GateResult | None = None
    for candidate in candidates:
        result = _validate_candidate(
            candidate,
            pr_number=pr_number,
            head_sha=head_sha,
            config=config,
        )
        if result.ok:
            return result
        if first_failure is None:
            first_failure = result
    return first_failure or _failure("receipt_missing", config)


def _api_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "quantforge-audit-receipt-gate",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _github_json(
    url: str,
    *,
    token: str | None,
    method: str = "GET",
    body: dict[str, Any] | None = None,
) -> tuple[Any, dict[str, str]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers=_api_headers(token),
    )
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            parsed = json.loads(raw) if raw else None
            return parsed, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"github_api_http_{exc.code}:{detail[:300]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"github_api_url_error:{exc.reason}") from exc


def _paged_github_json(url: str, *, token: str | None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = url
    while next_url:
        page, headers = _github_json(next_url, token=token)
        if not isinstance(page, list):
            raise RuntimeError("github_api_expected_list")
        items.extend(item for item in page if isinstance(item, dict))
        next_url = _next_link(headers.get("Link", ""))
    return items


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        section = part.strip()
        if 'rel="next"' not in section:
            continue
        start = section.find("<")
        end = section.find(">", start + 1)
        if start >= 0 and end > start:
            return section[start + 1 : end]
    return None


def _repo_api_url(api_url: str, repo: str, suffix: str) -> str:
    return f"{api_url.rstrip('/')}/repos/{repo}/{suffix.lstrip('/')}"


def _event_pr_number(event: dict[str, Any]) -> int | None:
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict) and isinstance(pull_request.get("number"), int):
        return int(pull_request["number"])
    issue = event.get("issue")
    if isinstance(issue, dict) and isinstance(issue.get("number"), int) and isinstance(issue.get("pull_request"), dict):
        return int(issue["number"])
    inputs = event.get("inputs")
    if isinstance(inputs, dict):
        raw = inputs.get("pr_number")
        if isinstance(raw, str) and raw.isdigit():
            return int(raw)
    return None


def _load_pr(event: dict[str, Any], *, repo: str, api_url: str, token: str | None) -> dict[str, Any] | None:
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        return pull_request
    pr_number = _event_pr_number(event)
    if pr_number is None:
        return None
    pr_url = _repo_api_url(api_url, repo, f"pulls/{pr_number}")
    pr, _headers = _github_json(pr_url, token=token)
    if not isinstance(pr, dict):
        raise RuntimeError("github_api_expected_pr_object")
    return pr


def _pr_head_sha(pr: dict[str, Any]) -> str:
    head = pr.get("head")
    if isinstance(head, dict) and isinstance(head.get("sha"), str):
        return head["sha"]
    raise RuntimeError("pull_request_head_sha_missing")


def _pr_number(pr: dict[str, Any]) -> int:
    number = pr.get("number")
    if isinstance(number, int):
        return number
    raise RuntimeError("pull_request_number_missing")


def _fetch_comments(*, repo: str, api_url: str, token: str | None, pr_number: int) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"per_page": "100"})
    url = _repo_api_url(api_url, repo, f"issues/{pr_number}/comments?{query}")
    return _paged_github_json(url, token=token)


def post_commit_status(
    *,
    repo: str,
    api_url: str,
    token: str | None,
    head_sha: str,
    result: GateResult,
) -> None:
    status_url = _repo_api_url(api_url, repo, f"statuses/{head_sha}")
    body: dict[str, Any] = {
        "state": result.state,
        "context": result.context,
        "description": result.description[:140],
    }
    if result.matching_comment_url:
        body["target_url"] = result.matching_comment_url
    _github_json(status_url, token=token, method="POST", body=body)


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify exact-head PR audit receipt.")
    parser.add_argument("--event-path", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    parser.add_argument("--comments-json", type=Path)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--allowed-issuers", default=os.environ.get("AUDIT_RECEIPT_ALLOWED_ISSUERS", ""))
    parser.add_argument("--allowed-auditors", default=os.environ.get("AUDIT_RECEIPT_ALLOWED_AUDITORS", ""))
    parser.add_argument("--max-age-hours", type=int, default=int(os.environ.get("AUDIT_RECEIPT_MAX_AGE_HOURS", "168")))
    parser.add_argument("--now-utc")
    parser.add_argument("--context", default=os.environ.get("AUDIT_RECEIPT_CONTEXT", DEFAULT_CONTEXT))
    parser.add_argument("--set-status", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.event_path is None:
        print("AUDIT_RECEIPT_GATE FAIL event_path_missing")
        return 1
    if not args.repo:
        print("AUDIT_RECEIPT_GATE FAIL github_repository_missing")
        return 1
    allowed_issuers = _split_csv(args.allowed_issuers)
    allowed_auditors = _split_csv(args.allowed_auditors)
    if not allowed_issuers:
        print("AUDIT_RECEIPT_GATE FAIL allowed_issuers_missing")
        return 1
    if not allowed_auditors:
        print("AUDIT_RECEIPT_GATE FAIL allowed_auditors_missing")
        return 1
    now = _parse_utc(args.now_utc) if args.now_utc else None
    if args.now_utc and now is None:
        print("AUDIT_RECEIPT_GATE FAIL now_utc_invalid")
        return 1
    config = ReceiptConfig(
        allowed_issuers=allowed_issuers,
        allowed_auditors=allowed_auditors,
        max_age_hours=args.max_age_hours,
        now=now,
        context=args.context,
    )
    try:
        event = _load_json_file(args.event_path)
        if not isinstance(event, dict):
            raise RuntimeError("event_json_not_object")
        pr = _load_pr(event, repo=args.repo, api_url=args.api_url, token=args.token)
        if pr is None:
            print("AUDIT_RECEIPT_GATE SKIP no_pull_request")
            return 0
        pr_number = _pr_number(pr)
        head_sha = _pr_head_sha(pr)
        comments = (
            _load_json_file(args.comments_json)
            if args.comments_json is not None
            else _fetch_comments(repo=args.repo, api_url=args.api_url, token=args.token, pr_number=pr_number)
        )
        if not isinstance(comments, list):
            raise RuntimeError("comments_json_not_list")
        result = evaluate_receipts(
            comments=comments,
            pr_number=pr_number,
            head_sha=head_sha,
            config=config,
        )
        if args.set_status:
            post_commit_status(
                repo=args.repo,
                api_url=args.api_url,
                token=args.token,
                head_sha=head_sha,
                result=result,
            )
    except Exception as exc:  # noqa: BLE001 - fail closed and surface the reason.
        result = _failure("gate_error", config, description=f"gate error: {exc}")
        if args.set_status:
            pr_number_for_status = None
            head_sha_for_status = None
            try:
                event = _load_json_file(args.event_path)
                pr = _load_pr(event, repo=args.repo, api_url=args.api_url, token=args.token) if isinstance(event, dict) else None
                if pr is not None:
                    pr_number_for_status = _pr_number(pr)
                    head_sha_for_status = _pr_head_sha(pr)
                    post_commit_status(
                        repo=args.repo,
                        api_url=args.api_url,
                        token=args.token,
                        head_sha=head_sha_for_status,
                        result=result,
                    )
            except Exception:
                pass
            suffix = f" pr={pr_number_for_status} head={head_sha_for_status}" if head_sha_for_status else ""
            print(f"AUDIT_RECEIPT_GATE FAIL {result.reason}{suffix} {result.description}")
        else:
            print(f"AUDIT_RECEIPT_GATE FAIL {result.reason} {result.description}")
        return 1
    print(f"AUDIT_RECEIPT_GATE {'PASS' if result.ok else 'FAIL'} {result.reason} {result.description}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
