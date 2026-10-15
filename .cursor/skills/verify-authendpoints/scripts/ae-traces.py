#!/usr/bin/env python3
"""Read AuthEndpoints spans from the Aspire dashboard API and summarize them.

The dashboard route is GET /api/telemetry/traces (OTLP JSON inside
{data, totalCount, returnedCount}). This script looks at span status,
exception events, db.statement text, and server-span duration. It does
not change the library.

See ../SKILL.md.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from typing import Any

REQUEST_NAME = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+")
STATEMENT_KEYS = ("db.statement", "db.query.text")
EMAIL_CODE_TABLE = "authendpointsemailcodes"
VERIFY_ROUTE = "POST /identity/emailCode/verify"

PAIRS = (
    {
        "id": "login",
        "route": "POST /identity/login",
        "existing": "existing user, wrong password",
        "unknown": "unknown user",
    },
    {
        "id": "email-code-send",
        "route": "POST /identity/emailCode/send",
        "existing": "existing user",
        "unknown": "unknown user",
    },
    {
        "id": "forgot-password",
        "route": "POST /identity/forgotPassword",
        "existing": "existing user",
        "unknown": "unknown user",
    },
    {
        "id": "register",
        "route": "POST /identity/register",
        "existing": "existing email",
        "unknown": "new email",
    },
    {
        "id": "passkey-login-options",
        "route": "POST /account/passkeys/requestOptions",
        "existing": "existing user",
        "unknown": "unknown user",
    },
)


@dataclass
class Event:
    name: str
    message: str


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_id: str
    name: str
    start_ns: int
    end_ns: int
    status_code: int
    status_message: str
    attributes: dict[str, str]
    events: list[Event] = field(default_factory=list)
    statement_key: str = ""
    statement: str = ""

    @property
    def duration_ms(self) -> float:
        if self.end_ns <= self.start_ns:
            return 0.0
        return (self.end_ns - self.start_ns) / 1_000_000

    @property
    def is_request(self) -> bool:
        return REQUEST_NAME.match(self.name) is not None or bool(self.attributes.get("http.route"))


@dataclass
class RequestTrace:
    request: Span
    spans: list[Span]

    @property
    def statements(self) -> list[tuple[str, str]]:
        ordered = sorted(
            (span for span in self.spans if span.statement),
            key=lambda span: (span.start_ns, span.span_id),
        )
        return [(span.statement_key, span.statement) for span in ordered]


@dataclass
class Finding:
    severity: str  # fail, flag
    text: str


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes"}


def attr_lookup(raw_attrs: list[dict[str, Any]] | None) -> dict[str, str]:
    found: dict[str, str] = {}
    for item in raw_attrs or []:
        key = item.get("key")
        if not key:
            continue
        value = item.get("value") or {}
        text = None
        for field_name in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if field_name in value and value[field_name] is not None:
                text = value[field_name]
                break
        if text is None:
            continue
        found[str(key)] = str(text)
    return found


def status_code(raw: dict[str, Any] | None) -> tuple[int, str]:
    status = raw or {}
    message = str(status.get("message") or "")
    code = status.get("code", 0)
    if isinstance(code, str):
        upper = code.strip().upper()
        if upper in {"2", "ERROR", "STATUS_CODE_ERROR"} or upper.endswith("_ERROR"):
            return 2, message
        if upper in {"1", "OK", "STATUS_CODE_OK"}:
            return 1, message
        return 0, message
    try:
        return int(code), message
    except (TypeError, ValueError):
        return 0, message


def as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_spans(document: dict[str, Any], service: str) -> list[Span]:
    spans: list[Span] = []
    data = document.get("data") or {}
    for resource_spans in data.get("resourceSpans") or []:
        resource_attrs = attr_lookup((resource_spans.get("resource") or {}).get("attributes"))
        service_name = resource_attrs.get("service.name", "")
        if service and service_name and service_name != service:
            continue
        for scope in resource_spans.get("scopeSpans") or []:
            for raw in scope.get("spans") or []:
                attrs = attr_lookup(raw.get("attributes"))
                code, message = status_code(raw.get("status"))
                events: list[Event] = []
                for event in raw.get("events") or []:
                    event_attrs = attr_lookup(event.get("attributes"))
                    event_message = event_attrs.get("exception.message") or event_attrs.get("message") or ""
                    events.append(Event(name=str(event.get("name") or ""), message=event_message))
                statement_key = ""
                statement = ""
                for key in STATEMENT_KEYS:
                    if attrs.get(key):
                        statement_key = key
                        statement = attrs[key]
                        break
                spans.append(
                    Span(
                        trace_id=str(raw.get("traceId") or ""),
                        span_id=str(raw.get("spanId") or ""),
                        parent_id=str(raw.get("parentSpanId") or ""),
                        name=str(raw.get("name") or ""),
                        start_ns=as_int(raw.get("startTimeUnixNano")),
                        end_ns=as_int(raw.get("endTimeUnixNano")),
                        status_code=code,
                        status_message=message,
                        attributes=attrs,
                        events=events,
                        statement_key=statement_key,
                        statement=statement,
                    )
                )
    return spans


class TraceFetchError(Exception):
    pass


def fetch_json(url: str) -> tuple[int, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(detail) if detail else {}
        except json.JSONDecodeError:
            payload = detail[:500]
        return exc.code, payload
    except urllib.error.URLError as exc:
        raise TraceFetchError(
            f"Could not reach the Aspire dashboard at {url}. Start it and retry. ({exc.reason})"
        ) from exc
    try:
        return status, json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise TraceFetchError(f"Dashboard API did not return JSON from {url}") from exc


def resource_keys(dashboard: str, service: str) -> list[str]:
    """Names to pass as repeated resource filters.

    Two live hosts both export service.name=authendpoints-demo. The dashboard
    then rejects ?resource=authendpoints-demo with 404 and keeps each instance
    under displayName "{name}-{instanceId}".
    """
    status, payload = fetch_json(dashboard.rstrip("/") + "/api/telemetry/resources")
    if status != 200 or not isinstance(payload, list):
        return [service] if service else []
    keys: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        if service and item.get("name") != service:
            continue
        if item.get("hasTraces") is False:
            continue
        display = str(item.get("displayName") or item.get("name") or "")
        if display and display not in keys:
            keys.append(display)
    if not keys and service:
        return [service]
    return keys


def fetch_document(dashboard: str, resource_key: str, limit: int, has_error: bool | None = None) -> dict[str, Any]:
    params: list[tuple[str, str]] = [("limit", str(limit))]
    if resource_key:
        params.append(("resource", resource_key))
    if has_error is True:
        params.append(("hasError", "true"))
    url = dashboard.rstrip("/") + "/api/telemetry/traces?" + urllib.parse.urlencode(params)
    status, payload = fetch_json(url)
    if status == 404:
        raise TraceFetchError(f"Dashboard traces API returned HTTP 404 for resource {resource_key}")
    if status != 200 or not isinstance(payload, dict):
        raise TraceFetchError(f"Dashboard traces API returned HTTP {status} for {url}")
    return payload


def load_spans(dashboard: str, service: str, limit: int) -> tuple[list[Span], int, int]:
    keys = resource_keys(dashboard, service)
    spans: list[Span] = []
    known: set[str] = set()
    total = 0
    returned = 0
    errors: list[str] = []
    for key in keys:
        try:
            document = fetch_document(dashboard, key, limit)
        except TraceFetchError as exc:
            errors.append(str(exc))
            continue
        total += int(document.get("totalCount") or 0)
        returned += int(document.get("returnedCount") or 0)
        for span in parse_spans(document, service):
            if span.span_id in known:
                continue
            known.add(span.span_id)
            spans.append(span)
        if int(document.get("returnedCount") or 0) < int(document.get("totalCount") or 0):
            try:
                error_doc = fetch_document(dashboard, key, limit, has_error=True)
            except TraceFetchError:
                continue
            for span in parse_spans(error_doc, service):
                if span.span_id in known:
                    continue
                known.add(span.span_id)
                spans.append(span)
    if not spans and errors and not keys:
        raise TraceFetchError("; ".join(errors))
    if not spans and errors and all("404" in error for error in errors):
        raise TraceFetchError(
            "No traces for service "
            f"{service}. The dashboard resource list did not match, or export has not flushed. "
            + "; ".join(errors)
        )
    return spans, total, returned


def port_matches(span: Span, port: str) -> bool:
    if not port:
        return True
    server_port = span.attributes.get("server.port", "")
    if server_port:
        return server_port == port
    destination = span.attributes.get("aspire.destination", "")
    if destination:
        return destination.endswith(":" + port)
    return False


def group_requests(spans: list[Span], since_ns: int, port: str) -> tuple[list[RequestTrace], list[Span]]:
    by_id = {span.span_id: span for span in spans if span.span_id}
    children: dict[str, list[Span]] = defaultdict(list)
    for span in spans:
        if span.parent_id:
            children[span.parent_id].append(span)

    def walk(root_id: str) -> list[Span]:
        found: list[Span] = []
        stack = list(children.get(root_id, []))
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current.span_id in seen:
                continue
            seen.add(current.span_id)
            found.append(current)
            stack.extend(children.get(current.span_id, []))
        return found

    requests: list[RequestTrace] = []
    covered: set[str] = set()
    http_spans = [span for span in spans if span.is_request and port_matches(span, port)]
    http_spans.sort(key=lambda span: span.start_ns)
    for http in http_spans:
        if since_ns and http.start_ns < since_ns:
            continue
        descendants = walk(http.span_id)
        covered.add(http.span_id)
        covered.update(span.span_id for span in descendants)
        requests.append(RequestTrace(request=http, spans=[http, *descendants]))

    orphans = []
    for span in spans:
        if span.span_id in covered:
            continue
        if since_ns and span.start_ns < since_ns:
            continue
        if port and not port_matches(span, port):
            continue
        orphans.append(span)
    return requests, orphans


def norm_sql(sql: str) -> str:
    return " ".join(sql.replace('"', "").replace("'", "").split())


def sql_keyword(sql: str) -> str:
    text = norm_sql(sql).lower()
    return text.split(" ", 1)[0] if text else ""


def on_email_code_table(sql: str) -> bool:
    return EMAIL_CODE_TABLE in norm_sql(sql).lower()


def is_consume_update(sql: str) -> bool:
    text = norm_sql(sql).lower()
    return (
        text.startswith("update")
        and on_email_code_table(sql)
        and "set consumedat" in text
        and "consumedat is null" in text
    )


def is_attempt_reserve(sql: str) -> bool:
    text = norm_sql(sql).lower()
    return text.startswith("update") and on_email_code_table(sql) and "set attempts" in text


def is_email_code_write(sql: str) -> bool:
    return sql_keyword(sql) in {"update", "insert", "delete"} and on_email_code_table(sql)


def http_status(span: Span) -> str:
    return span.attributes.get("http.response.status_code", "")


def short_trace(trace_id: str) -> str:
    return trace_id[:16]


def exception_message(span: Span) -> str:
    messages = [event.message for event in span.events if event.name.lower() == "exception" and event.message]
    if messages:
        return messages[0]
    return ""


def error_findings(requests: list[RequestTrace], orphans: list[Span]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def consider(span: Span, route: str) -> None:
        route_bit = f" route={route}" if route else ""
        if span.status_code == 2:
            message = span.status_message or exception_message(span) or "(no status message)"
            key = ("error", span.span_id, message)
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        "fail",
                        f"error span name={span.name}{route_bit} trace={short_trace(span.trace_id)} message={message}",
                    )
                )
        for event in span.events:
            if event.name.lower() != "exception":
                continue
            message = event.message or "(no exception message)"
            key = ("exception", span.span_id, message)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    "fail",
                    f"exception event name={span.name}{route_bit} trace={short_trace(span.trace_id)} message={message}",
                )
            )

    for request in requests:
        for span in request.spans:
            consider(span, request.request.name)
    for span in orphans:
        consider(span, "")
    return findings


def repeated_statements(request: RequestTrace) -> list[tuple[int, str]]:
    counts: dict[str, int] = defaultdict(int)
    for _key, statement in request.statements:
        counts[norm_sql(statement)] += 1
    repeated = [(count, statement) for statement, count in counts.items() if count >= 2 and statement]
    repeated.sort(key=lambda item: (-item[0], item[1]))
    return repeated


def nplus1_findings(requests: list[RequestTrace]) -> list[Finding]:
    findings: list[Finding] = []
    for request in requests:
        for count, statement in repeated_statements(request):
            preview = statement if len(statement) <= 180 else statement[:177] + "..."
            findings.append(
                Finding(
                    "flag",
                    "N+1 repeated identical statement "
                    f"x{count} in {request.request.name} trace={short_trace(request.request.trace_id)}: {preview}",
                )
            )
    return findings


def email_code_findings(requests: list[RequestTrace], require: bool) -> list[Finding]:
    successes = [
        request
        for request in requests
        if request.request.name == VERIFY_ROUTE and http_status(request.request) == "200"
    ]
    if not successes:
        if require:
            return [Finding("fail", "email-code verify: not observed (no HTTP 200 POST /identity/emailCode/verify in this window)")]
        return []
    findings: list[Finding] = []
    for request in successes:
        statements = [statement for _key, statement in request.statements]
        if not statements:
            findings.append(
                Finding(
                    "fail",
                    "email-code verify: no db.statement spans "
                    f"trace={short_trace(request.request.trace_id)}",
                )
            )
            continue
        consumes = [statement for statement in statements if is_consume_update(statement)]
        reserves = [statement for statement in statements if is_attempt_reserve(statement)]
        other = [
            statement
            for statement in statements
            if is_email_code_write(statement) and not is_consume_update(statement) and not is_attempt_reserve(statement)
        ]
        problems = []
        if len(consumes) != 1:
            problems.append(f"ConsumedAt conditional updates={len(consumes)} (want 1)")
        if len(reserves) != 1:
            problems.append(f"Attempts reservation updates={len(reserves)} (want 1)")
        if other:
            problems.append(f"other AuthEndpointsEmailCodes writes={len(other)}")
        prefix = f"trace={short_trace(request.request.trace_id)}"
        if problems:
            findings.append(Finding("fail", "email-code verify: " + prefix + " " + "; ".join(problems)))
        else:
            findings.append(
                Finding(
                    "info",
                    "email-code verify: pass "
                    + prefix
                    + " one conditional ConsumedAt update, one Attempts reservation, no other email-code writes",
                )
            )
    return [finding for finding in findings if finding.severity != "info"] + [
        finding for finding in findings if finding.severity == "info"
    ]


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(statistics.median(values))


def timing_gap_findings(
    labels: list[dict[str, Any]],
    by_trace: dict[str, RequestTrace],
    gap_ms: float,
    gap_ratio: float,
) -> list[Finding]:
    findings: list[Finding] = []
    for pair in PAIRS:
        rows = [label for label in labels if label.get("pair") == pair["id"] and not label.get("skipped")]
        if not rows:
            continue
        durations: dict[str, list[float]] = {"existing": [], "unknown": []}
        missing = 0
        for label in rows:
            trace_id = str(label.get("traceId") or "")
            request = by_trace.get(trace_id) or by_trace.get(trace_id.lower())
            if request is None:
                missing += 1
                continue
            cohort = str(label.get("cohort") or "")
            if cohort not in durations:
                continue
            durations[cohort].append(request.request.duration_ms)
        for cohort, samples in durations.items():
            if len(samples) < 2:
                findings.append(
                    Finding(
                        "flag",
                        f"timing {pair['id']}: insufficient {cohort} samples ({len(samples)}); missing_traces={missing}",
                    )
                )
        existing = durations["existing"]
        unknown = durations["unknown"]
        if len(existing) < 2 or len(unknown) < 2:
            continue
        existing_median = median(existing)
        unknown_median = median(unknown)
        gap = abs(existing_median - unknown_median)
        small = min(existing_median, unknown_median)
        ratio = (max(existing_median, unknown_median) / small) if small > 0 else float("inf")
        large = gap >= gap_ms and (ratio >= gap_ratio or small == 0)
        slower = pair["existing"] if existing_median > unknown_median else pair["unknown"]
        text = (
            f"timing {pair['id']} {pair['route']}: "
            f"existing median_ms={existing_median:.1f} n={len(existing)} "
            f"({pair['existing']}); "
            f"unknown median_ms={unknown_median:.1f} n={len(unknown)} "
            f"({pair['unknown']}); "
            f"gap_ms={gap:.1f} ratio={ratio:.2f} slower={slower}"
        )
        if large:
            findings.append(Finding("flag", text + " FLAG possible timing side channel"))
        else:
            findings.append(Finding("info", text))
    return findings


def slow_findings(requests: list[RequestTrace], slow_ms: float) -> list[Finding]:
    findings = []
    for request in requests:
        duration = request.request.duration_ms
        if duration >= slow_ms:
            findings.append(
                Finding(
                    "flag",
                    "slow span "
                    f"name={request.request.name} duration_ms={duration:.1f} "
                    f"trace={short_trace(request.request.trace_id)} threshold_ms={slow_ms:.0f}",
                )
            )
    return findings


def one_line(sql: str, limit: int = 500) -> str:
    text = norm_sql(sql)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def format_samples(values: list[float]) -> str:
    return ",".join(f"{value:.1f}" for value in values)


def render_summary(
    *,
    service: str,
    dashboard: str,
    since_ns: int,
    total: int,
    returned: int,
    requests: list[RequestTrace],
    error_rows: list[Finding],
    sql_flags: list[Finding],
    email_rows: list[Finding],
    timing_rows: list[Finding],
    slow_rows: list[Finding],
    skips: list[dict[str, Any]],
    labels: list[dict[str, Any]],
    section: str,
    truncated: bool,
) -> tuple[str, int]:
    fail = [row for row in error_rows + email_rows + timing_rows + slow_rows + sql_flags if row.severity == "fail"]
    flags = [row for row in error_rows + email_rows + timing_rows + slow_rows + sql_flags if row.severity == "flag"]
    if section == "errors":
        fail = [row for row in error_rows if row.severity == "fail"]
        flags = []
    elif section == "sql":
        fail = [row for row in email_rows if row.severity == "fail"]
        flags = [row for row in sql_flags if row.severity == "flag"]
    elif section == "timing":
        fail = [row for row in timing_rows if row.severity == "fail"]
        flags = [row for row in timing_rows + slow_rows if row.severity == "flag"]

    if fail:
        result = "fail"
        exit_code = 1
    elif flags:
        result = "flag"
        exit_code = 2 if not truthy(os.environ.get("AE_TRACES_STRICT")) else 1
    else:
        result = "pass"
        exit_code = 0

    lines = [
        "AuthEndpoints trace summary",
        f"result: {result}",
        f"service: {service}",
        f"dashboard: {dashboard.rstrip('/')}/api/telemetry/traces?resource={urllib.parse.quote(service)}",
        f"window_since: {format_time(since_ns) if since_ns else 'unbounded'}",
        f"dashboard_traces: returned={returned} total={total}",
        f"request_traces: {len(requests)}",
    ]
    if truncated:
        lines.append(
            "note: dashboard returned the most recent traces only "
            f"(returned={returned} total={total}); narrow the window with `ae-http.sh traces mark`"
        )
    lines.append("")

    show_errors = section in {"all", "errors"}
    show_sql = section in {"all", "sql"}
    show_timing = section in {"all", "timing"}

    if show_errors:
        error_count = sum(1 for row in error_rows if row.text.startswith("error span"))
        exception_count = sum(1 for row in error_rows if row.text.startswith("exception event"))
        lines.append("Errors")
        lines.append(f"error spans: {error_count}")
        lines.append(f"exception events: {exception_count}")
        if error_rows:
            for row in error_rows:
                lines.append(row.text)
        else:
            lines.append("pass: zero error spans and zero exception events")
        lines.append("")

    if show_sql:
        lines.append("SQL")
        if not requests:
            lines.append("no request traces in this window")
        for request in requests:
            status = http_status(request.request) or "-"
            lines.append(
                f"{request.request.name} status={status} "
                f"duration_ms={request.request.duration_ms:.1f} "
                f"trace={short_trace(request.request.trace_id)}"
            )
            statements = request.statements
            if not statements:
                lines.append("  (no db.statement)")
            for index, (key, statement) in enumerate(statements, start=1):
                suffix = "" if key == "db.statement" else f" [{key}]"
                lines.append(f"  {index}. {one_line(statement)}{suffix}")
            repeats = repeated_statements(request)
            for count, statement in repeats:
                lines.append(f"  N+1 x{count}: {one_line(statement, 180)}")
        lines.append("email-code verify")
        info_or_fail = [row for row in email_rows if row.severity in {"fail", "info"}]
        if not info_or_fail and not any(row.severity == "fail" for row in email_rows):
            lines.append("not observed")
        for row in email_rows:
            if row.severity == "flag":
                continue
            lines.append(row.text)
        if not sql_flags:
            lines.append("N+1 flags: none")
        else:
            lines.append(f"N+1 flags: {len(sql_flags)}")
            for row in sql_flags[:40]:
                lines.append(row.text)
            if len(sql_flags) > 40:
                lines.append(f"and {len(sql_flags) - 40} more")
        lines.append("")

    if show_timing:
        lines.append("Timing")
        by_route: dict[str, list[float]] = defaultdict(list)
        for request in requests:
            by_route[request.request.name].append(request.request.duration_ms)
        if not by_route:
            lines.append("per-route: none")
        else:
            lines.append("per-route server span duration_ms")
            for route in sorted(by_route):
                samples = sorted(by_route[route])
                lines.append(
                    f"  {route} n={len(samples)} min={samples[0]:.1f} "
                    f"median={median(samples):.1f} max={samples[-1]:.1f}"
                )
        lines.append("enumeration")
        if skips:
            for skip in skips:
                lines.append(f"  skipped {skip.get('pair')}: {skip.get('reason')}")
        pair_rows = [row for row in timing_rows if row.text.startswith("timing ")]
        if not pair_rows and not skips:
            lines.append("  no existing-vs-unknown samples (run `ae-http.sh traces probe`)")
        elif labels and not pair_rows:
            lines.append("  labels were present but no pair produced a median")
        for row in pair_rows:
            lines.append("  " + row.text)
        if not slow_rows:
            lines.append(f"slow spans: none (threshold_ms={env_float('AE_SLOW_SPAN_MS', 750):.0f})")
        else:
            lines.append(f"slow spans: {len(slow_rows)}")
            for row in slow_rows[:20]:
                lines.append(row.text)
        lines.append("")

    lines.append(f"result: {result}")
    if exit_code == 1:
        lines.append("exit: 1 (error span, exception event, or failed email-code SQL assert)")
    elif exit_code == 2:
        lines.append("exit: 2 (N+1, timing side channel, or slow span flag)")
    else:
        lines.append("exit: 0")
    return "\n".join(lines) + "\n", exit_code


def format_time(ns: int) -> str:
    if ns <= 0:
        return "unset"
    return datetime.fromtimestamp(ns / 1_000_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_since(path: str) -> int:
    if not path or not os.path.isfile(path):
        return 0
    raw = open(path, encoding="utf-8").read().strip()
    return as_int(raw)


def write_since(path: str, ns: int | None = None) -> int:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    value = time.time_ns() if ns is None else ns
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(str(value) + "\n")
    return value


def evidence_paths() -> tuple[str, str, str]:
    run_dir = os.environ.get("AE_RUN_DIR", "")
    evidence = os.environ.get("AE_EVIDENCE_DIR", "")
    if not evidence:
        evidence = os.path.join(run_dir, "evidence") if run_dir else os.path.join("/tmp", "authendpoints-traces")
    since_path = os.path.join(run_dir, "traces.since") if run_dir else ""
    return evidence, since_path, run_dir


def read_labels(path: str) -> list[dict[str, Any]]:
    if not os.path.isfile(path):
        return []
    rows = []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def analyze(section: str, wait: bool, require_email_code: bool) -> int:
    evidence, since_path, _run_dir = evidence_paths()
    os.makedirs(evidence, exist_ok=True)
    service = os.environ.get("OTEL_SERVICE_NAME") or os.environ.get("AE_SERVICE_NAME") or "authendpoints-demo"
    dashboard = os.environ.get("AE_DASHBOARD_URL") or "http://localhost:18888"
    limit = env_int("AE_TRACE_LIMIT", 1000)
    port = os.environ.get("AE_PORT", "").strip()
    since_ns = read_since(since_path)
    flush_seconds = env_float("AE_TRACE_FLUSH_SECONDS", 6)
    if wait and flush_seconds > 0:
        print(f"waiting {flush_seconds:.0f}s for the OTLP batch exporter", file=sys.stderr)
        time.sleep(flush_seconds)
    try:
        spans, total, returned = load_spans(dashboard, service, limit)
    except TraceFetchError as exc:
        raise SystemExit(str(exc)) from exc
    requests, orphans = group_requests(spans, since_ns, port)
    label_path = os.path.join(evidence, "trace-labels.jsonl")
    labels = read_labels(label_path)
    skips = [label for label in labels if label.get("skipped")]
    by_trace = {request.request.trace_id: request for request in requests}
    error_rows = error_findings(requests, orphans)
    sql_flags = nplus1_findings(requests)
    email_rows = email_code_findings(requests, require_email_code)
    # email_code_findings returns info rows too; keep them for the report but
    # they are not flags. Filter severity below.
    gap_ms = env_float("AE_TIMING_GAP_MS", 25)
    gap_ratio = env_float("AE_TIMING_GAP_RATIO", 2.0)
    slow_ms = env_float("AE_SLOW_SPAN_MS", 750)
    timing_rows = timing_gap_findings(labels, by_trace, gap_ms, gap_ratio)
    slow_rows = slow_findings(requests, slow_ms)
    text, exit_code = render_summary(
        service=service,
        dashboard=dashboard,
        since_ns=since_ns,
        total=total,
        returned=returned,
        requests=requests,
        error_rows=error_rows,
        sql_flags=sql_flags,
        email_rows=email_rows,
        timing_rows=timing_rows,
        slow_rows=slow_rows,
        skips=skips,
        labels=labels,
        section=section,
        truncated=returned < total,
    )
    summary_path = os.path.join(evidence, "traces-summary.txt")
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write(text)
    print(f"wrote {summary_path}", file=sys.stderr)
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    export_off = endpoint is not None and not endpoint.strip()
    if not requests and not orphans and not export_off and exit_code == 0:
        print("no spans for this service and port in the window", file=sys.stderr)
        return 1
    return exit_code


class ProbeClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        csrf: str = "",
        trace_id: str = "",
    ) -> tuple[int, bytes, str]:
        if not trace_id:
            trace_id = secrets.token_hex(16)
        parent = secrets.token_hex(8)
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {
            "Origin": self.base_url,
            "traceparent": f"00-{trace_id}-{parent}-01",
            "Accept": "application/json, text/plain, */*",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["RequestVerificationToken"] = csrf
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, response.read(), trace_id
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), trace_id

    def request_retry(self, method: str, path: str, body: dict[str, Any] | None = None, csrf: str = "") -> tuple[int, bytes, str]:
        status = 0
        payload = b""
        trace_id = ""
        for attempt in range(4):
            status, payload, trace_id = self.request(method, path, body, csrf)
            if status != 429:
                return status, payload, trace_id
            time.sleep(min(2 ** attempt, 10))
        return status, payload, trace_id

    def csrf_token(self) -> str:
        status, payload, _trace = self.request("GET", "/identity/csrfToken")
        if status != 200:
            status, payload, _trace = self.request("GET", "/auth/csrfToken")
        if status != 200:
            raise RuntimeError(f"csrf token request returned HTTP {status}")
        document = json.loads(payload.decode("utf-8"))
        token = document.get("csrfToken") or document.get("CsrfToken")
        if not token:
            raise RuntimeError("csrf response had no csrfToken")
        return str(token)


def confirm_user(client: ProbeClient, email: str) -> None:
    status, payload, _trace = client.request("GET", "/test/mailbox")
    if status != 200:
        raise RuntimeError(f"GET /test/mailbox returned HTTP {status}")
    items = json.loads(payload.decode("utf-8"))
    if not isinstance(items, list):
        raise RuntimeError("mailbox payload was not a list")
    link = ""
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("email") != email or item.get("kind") != "confirm":
            continue
        body = html.unescape(str(item.get("body") or ""))
        match = re.search(r"https?://\S+", body) or re.search(r"/identity/confirmEmail\?\S+", body)
        if match:
            link = match.group(0).rstrip("\"'")
            break
    if not link:
        raise RuntimeError("confirmation link was not in the mailbox")
    if link.startswith("/"):
        path = link
    else:
        parsed = urllib.parse.urlparse(link)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    status, _payload, _trace = client.request("GET", path)
    if status != 200:
        raise RuntimeError(f"confirmEmail returned HTTP {status}")


def email_code_for(client: ProbeClient, email: str) -> str:
    status, payload, _trace = client.request("GET", "/test/mailbox")
    if status != 200:
        raise RuntimeError(f"GET /test/mailbox returned HTTP {status}")
    items = json.loads(payload.decode("utf-8"))
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("email") != email or item.get("kind") != "email-code":
            continue
        body = str(item.get("body") or "").strip()
        if body and "http" not in body.lower() and len(body) <= 16:
            return body
    raise RuntimeError("email-code mailbox item was missing")


def record(labels: list[dict[str, Any]], pair: str, route: str, cohort: str, trace_id: str, status: int) -> None:
    labels.append(
        {
            "pair": pair,
            "route": route,
            "cohort": cohort,
            "traceId": trace_id,
            "httpStatus": status,
        }
    )


def cmd_probe() -> int:
    evidence, since_path, run_dir = evidence_paths()
    if not run_dir or not os.path.isdir(run_dir):
        raise SystemExit("AE_RUN_DIR is missing. Launch the host with ae-http.sh before traces probe.")
    base = os.environ.get("AE_BASE_URL", "").rstrip("/")
    if not base:
        raise SystemExit("AE_BASE_URL is missing. Launch the host with ae-http.sh before traces probe.")
    os.makedirs(evidence, exist_ok=True)
    if not os.path.isfile(since_path):
        write_since(since_path)
    client = ProbeClient(base)
    password = "Passw0rd!"
    stamp = secrets.token_hex(4)
    emails = [f"probe-{stamp}-{index}@test.local" for index in (1, 2, 3)]
    labels: list[dict[str, Any]] = []
    print("probe: register new vs existing", file=sys.stderr)
    for index, email in enumerate(emails):
        status, _payload, trace_id = client.request_retry(
            "POST", "/identity/register", {"email": email, "password": password}
        )
        if status != 200:
            raise SystemExit(f"register {email} returned HTTP {status}")
        record(labels, "register", "POST /identity/register", "unknown", trace_id, status)
        if index == 0:
            primary = email
    for _ in range(2):
        status, _payload, trace_id = client.request_retry(
            "POST", "/identity/register", {"email": primary, "password": password}
        )
        if status != 200:
            raise SystemExit(f"duplicate register returned HTTP {status}")
        record(labels, "register", "POST /identity/register", "existing", trace_id, status)
    print("probe: confirm users before send and forgot-password", file=sys.stderr)
    for email in emails:
        confirm_user(client, email)

    print("probe: email-code send and verify", file=sys.stderr)
    send_status, _payload, _trace = client.request(
        "POST", "/identity/emailCode/send", {"email": emails[1]}
    )
    if send_status == 404:
        labels.append(
            {
                "skipped": True,
                "pair": "email-code-send",
                "reason": "POST /identity/emailCode/send returned 404 (launch with AE_EMAIL_CODE=true)",
            }
        )
    else:
        if send_status != 200:
            raise SystemExit(f"email-code send for existing user returned HTTP {send_status}")
        record(labels, "email-code-send", "POST /identity/emailCode/send", "existing", _trace, send_status)
        status, _payload, trace_id = client.request_retry(
            "POST", "/identity/emailCode/send", {"email": emails[2]}
        )
        if status != 200:
            raise SystemExit(f"email-code send for existing user returned HTTP {status}")
        record(labels, "email-code-send", "POST /identity/emailCode/send", "existing", trace_id, status)
        for index in range(2):
            status, _payload, trace_id = client.request_retry(
                "POST",
                "/identity/emailCode/send",
                {"email": f"nobody-send-{stamp}-{index}@test.local"},
            )
            if status != 200:
                raise SystemExit(f"email-code send for unknown user returned HTTP {status}")
            record(labels, "email-code-send", "POST /identity/emailCode/send", "unknown", trace_id, status)
        code = email_code_for(client, emails[1])
        status, _payload, trace_id = client.request_retry(
            "POST",
            "/identity/emailCode/verify",
            {"email": emails[1], "code": code},
        )
        if status != 200:
            raise SystemExit(f"email-code verify returned HTTP {status}")

    print("probe: login existing vs unknown", file=sys.stderr)
    for _ in range(3):
        status, _payload, trace_id = client.request_retry(
            "POST", "/identity/login", {"email": primary, "password": "WrongPass1!"}
        )
        if status != 401:
            raise SystemExit(f"existing-user login returned HTTP {status}")
        record(labels, "login", "POST /identity/login", "existing", trace_id, status)
        status, _payload, trace_id = client.request_retry(
            "POST",
            "/identity/login",
            {"email": f"nobody-login-{stamp}-{secrets.token_hex(3)}@test.local", "password": "WrongPass1!"},
        )
        if status != 401:
            raise SystemExit(f"unknown-user login returned HTTP {status}")
        record(labels, "login", "POST /identity/login", "unknown", trace_id, status)

    print("probe: forgot password", file=sys.stderr)
    for index in range(2):
        status, _payload, trace_id = client.request_retry("POST", "/identity/forgotPassword", {"email": primary})
        if status != 200:
            raise SystemExit(f"forgot password for existing user returned HTTP {status}")
        record(labels, "forgot-password", "POST /identity/forgotPassword", "existing", trace_id, status)
        status, _payload, trace_id = client.request_retry(
            "POST",
            "/identity/forgotPassword",
            {"email": f"nobody-forgot-{stamp}-{index}@test.local"},
        )
        if status != 200:
            raise SystemExit(f"forgot password for unknown user returned HTTP {status}")
        record(labels, "forgot-password", "POST /identity/forgotPassword", "unknown", trace_id, status)

    print("probe: passkey login options", file=sys.stderr)
    try:
        token = client.csrf_token()
    except RuntimeError as exc:
        labels.append({"skipped": True, "pair": "passkey-login-options", "reason": str(exc)})
        token = ""
    if token:
        first_status, _payload, first_trace = client.request(
            "POST",
            "/account/passkeys/requestOptions",
            {"email": primary},
            csrf=token,
        )
        if first_status == 404:
            labels.append(
                {
                    "skipped": True,
                    "pair": "passkey-login-options",
                    "reason": "POST /account/passkeys/requestOptions returned 404",
                }
            )
        else:
            if first_status != 200:
                raise SystemExit(f"passkey options for existing user returned HTTP {first_status}")
            record(
                labels,
                "passkey-login-options",
                "POST /account/passkeys/requestOptions",
                "existing",
                first_trace,
                first_status,
            )
            status, _payload, trace_id = client.request_retry(
                "POST",
                "/account/passkeys/requestOptions",
                {"email": primary},
                csrf=token,
            )
            if status != 200:
                raise SystemExit(f"passkey options for existing user returned HTTP {status}")
            record(
                labels,
                "passkey-login-options",
                "POST /account/passkeys/requestOptions",
                "existing",
                trace_id,
                status,
            )
            for index in range(2):
                status, _payload, trace_id = client.request_retry(
                    "POST",
                    "/account/passkeys/requestOptions",
                    {"email": f"nobody-pk-{stamp}-{index}@test.local"},
                    csrf=token,
                )
                if status != 200:
                    raise SystemExit(f"passkey options for unknown user returned HTTP {status}")
                record(
                    labels,
                    "passkey-login-options",
                    "POST /account/passkeys/requestOptions",
                    "unknown",
                    trace_id,
                    status,
                )

    label_path = os.path.join(evidence, "trace-labels.jsonl")
    with open(label_path, "w", encoding="utf-8") as handle:
        for label in labels:
            handle.write(json.dumps(label, separators=(",", ":")) + "\n")
    print(f"wrote {label_path}", file=sys.stderr)
    require = not any(label.get("pair") == "email-code-send" and label.get("skipped") for label in labels)
    return analyze("all", wait=True, require_email_code=require)


def cmd_mark() -> int:
    _evidence, since_path, run_dir = evidence_paths()
    if not run_dir:
        raise SystemExit("AE_RUN_DIR is missing.")
    os.makedirs(run_dir, exist_ok=True)
    value = write_since(since_path)
    print(f"traces.since {value} ({format_time(value)})")
    return 0


def self_test() -> int:
    consume = """
UPDATE "AuthEndpointsEmailCodes" AS "a"
SET "ConsumedAt" = @p
WHERE "a"."Id" = @row_Id AND "a"."ConsumedAt" IS NULL AND "a"."SupersededAt" IS NULL
AND "a"."ExpiresAt" > @now AND "a"."Attempts" <= @maxAttempts
"""
    reserve = """
UPDATE "AuthEndpointsEmailCodes" AS "a"
SET "Attempts" = "a"."Attempts" + ?
WHERE "a"."Id" = @row_Id AND "a"."ConsumedAt" IS NULL AND "a"."SupersededAt" IS NULL
"""
    user_select = 'SELECT "a"."Id" FROM "AspNetUsers" AS "a" WHERE "a"."NormalizedUserName" = @normalizedUserName'
    document = {
        "data": {
            "resourceSpans": [
                {
                    "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "authendpoints-demo"}}]},
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "traceId": "abc123",
                                    "spanId": "parent01",
                                    "name": "POST /identity/emailCode/verify",
                                    "startTimeUnixNano": "100",
                                    "endTimeUnixNano": "5100000",
                                    "attributes": [
                                        {"key": "http.response.status_code", "value": {"stringValue": "200"}},
                                        {"key": "server.port", "value": {"stringValue": "5091"}},
                                        {"key": "http.route", "value": {"stringValue": "/identity/emailCode/verify"}},
                                    ],
                                },
                                {
                                    "traceId": "abc123",
                                    "spanId": "child1",
                                    "parentSpanId": "parent01",
                                    "name": "main",
                                    "startTimeUnixNano": "200",
                                    "endTimeUnixNano": "300",
                                    "attributes": [{"key": "db.statement", "value": {"stringValue": consume}}],
                                },
                                {
                                    "traceId": "abc123",
                                    "spanId": "child2",
                                    "parentSpanId": "parent01",
                                    "name": "main",
                                    "startTimeUnixNano": "300",
                                    "endTimeUnixNano": "400",
                                    "attributes": [{"key": "db.statement", "value": {"stringValue": reserve}}],
                                },
                                {
                                    "traceId": "abc123",
                                    "spanId": "child3",
                                    "parentSpanId": "parent01",
                                    "name": "main",
                                    "startTimeUnixNano": "400",
                                    "endTimeUnixNano": "500",
                                    "attributes": [{"key": "db.statement", "value": {"stringValue": user_select}}],
                                },
                                {
                                    "traceId": "abc123",
                                    "spanId": "child4",
                                    "parentSpanId": "parent01",
                                    "name": "main",
                                    "startTimeUnixNano": "500",
                                    "endTimeUnixNano": "600",
                                    "attributes": [{"key": "db.statement", "value": {"stringValue": user_select}}],
                                },
                                {
                                    "traceId": "err1",
                                    "spanId": "errspan",
                                    "name": "POST /identity/login",
                                    "startTimeUnixNano": "100",
                                    "endTimeUnixNano": "200",
                                    "status": {"code": "STATUS_CODE_ERROR", "message": "login failed hard"},
                                    "attributes": [
                                        {"key": "server.port", "value": {"intValue": "5091"}},
                                        {"key": "http.response.status_code", "value": {"intValue": 500}},
                                    ],
                                    "events": [
                                        {
                                            "name": "exception",
                                            "attributes": [
                                                {"key": "exception.message", "value": {"stringValue": "boom"}}
                                            ],
                                        }
                                    ],
                                },
                            ]
                        }
                    ],
                }
            ]
        }
    }
    spans = parse_spans(document, "authendpoints-demo")
    requests, orphans = group_requests(spans, 0, "5091")
    assert len(requests) == 2, len(requests)
    verify = next(request for request in requests if request.request.name == VERIFY_ROUTE)
    assert len(verify.statements) == 4
    email_rows = email_code_findings(requests, require=True)
    assert any(row.severity == "info" and "pass" in row.text for row in email_rows), email_rows
    flags = nplus1_findings(requests)
    assert any("x2" in row.text and "NormalizedUserName" in row.text for row in flags), flags
    errors = error_findings(requests, orphans)
    assert any(row.text.startswith("error span name=POST /identity/login") and "login failed hard" in row.text for row in errors), errors
    assert any(row.text.startswith("exception event") and "message=boom" in row.text for row in errors), errors

    broken = RequestTrace(
        request=Span(
            trace_id="bad",
            span_id="b",
            parent_id="",
            name=VERIFY_ROUTE,
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={"http.response.status_code": "200"},
        ),
        spans=[],
    )
    broken.spans = [
        broken.request,
        Span(
            trace_id="bad",
            span_id="c1",
            parent_id="b",
            name="main",
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={},
            statement_key="db.statement",
            statement=consume,
        ),
        Span(
            trace_id="bad",
            span_id="c2",
            parent_id="b",
            name="main",
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={},
            statement_key="db.statement",
            statement=consume,
        ),
    ]
    failed = email_code_findings([broken], require=False)
    assert any(row.severity == "fail" and "ConsumedAt conditional updates=2" in row.text for row in failed), failed

    insert = Span(
        trace_id="bad2",
        span_id="i",
        parent_id="b2",
        name="main",
        start_ns=1,
        end_ns=2,
        status_code=0,
        status_message="",
        attributes={},
        statement_key="db.statement",
        statement='INSERT INTO "AuthEndpointsEmailCodes" ("Id") VALUES (@p0);',
    )
    extra = RequestTrace(
        request=Span(
            trace_id="bad2",
            span_id="b2",
            parent_id="",
            name=VERIFY_ROUTE,
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={"http.response.status_code": "200"},
        ),
        spans=[],
    )
    extra.spans = [
        extra.request,
        Span(
            trace_id="bad2",
            span_id="c",
            parent_id="b2",
            name="main",
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={},
            statement_key="db.statement",
            statement=consume,
        ),
        Span(
            trace_id="bad2",
            span_id="r",
            parent_id="b2",
            name="main",
            start_ns=1,
            end_ns=2,
            status_code=0,
            status_message="",
            attributes={},
            statement_key="db.statement",
            statement=reserve,
        ),
        insert,
    ]
    extra_findings = email_code_findings([extra], require=False)
    assert any("other AuthEndpointsEmailCodes writes=1" in row.text for row in extra_findings), extra_findings

    slow_request = RequestTrace(
        request=Span(
            trace_id="slow",
            span_id="s",
            parent_id="",
            name="POST /identity/login",
            start_ns=0,
            end_ns=900_000_000,
            status_code=0,
            status_message="",
            attributes={},
        ),
        spans=[],
    )
    slow_request.spans = [slow_request.request]
    assert slow_findings([slow_request], 750)

    by_trace = {
        "t1": RequestTrace(
            request=Span("t1", "a", "", "POST /identity/login", 0, 40_000_000, 0, "", {}),
            spans=[],
        ),
        "t2": RequestTrace(
            request=Span("t2", "b", "", "POST /identity/login", 0, 50_000_000, 0, "", {}),
            spans=[],
        ),
        "t3": RequestTrace(
            request=Span("t3", "c", "", "POST /identity/login", 0, 5_000_000, 0, "", {}),
            spans=[],
        ),
        "t4": RequestTrace(
            request=Span("t4", "d", "", "POST /identity/login", 0, 6_000_000, 0, "", {}),
            spans=[],
        ),
    }
    for request in by_trace.values():
        request.spans = [request.request]
    labels = [
        {"pair": "login", "cohort": "existing", "traceId": "t1"},
        {"pair": "login", "cohort": "existing", "traceId": "t2"},
        {"pair": "login", "cohort": "unknown", "traceId": "t3"},
        {"pair": "login", "cohort": "unknown", "traceId": "t4"},
    ]
    gaps = timing_gap_findings(labels, by_trace, gap_ms=25, gap_ratio=2)
    assert any(row.severity == "flag" and "possible timing side channel" in row.text for row in gaps), gaps

    numeric = status_code({"code": 2, "message": "x"})
    assert numeric == (2, "x")
    print("self-test: pass")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Summarize AuthEndpoints spans from the Aspire dashboard.")
    sub = parser.add_subparsers(dest="command")
    summary = sub.add_parser("summary", help="Write the full trace summary for spans since launch.")
    summary.add_argument("--section", choices=("all", "errors", "sql", "timing"), default="all")
    summary.add_argument("--no-wait", action="store_true")
    summary.add_argument("--require-email-code-verify", action="store_true")
    for name in ("errors", "sql", "timing"):
        command = sub.add_parser(name, help=f"Write only the {name} section.")
        command.add_argument("--no-wait", action="store_true")
        command.add_argument("--require-email-code-verify", action="store_true")
    sub.add_parser("probe", help="Drive enumeration-sensitive routes, then write the summary.")
    sub.add_parser("mark", help="Set the trace window start to now.")
    sub.add_parser("self-test", help="Check the summary logic without a dashboard.")
    args = parser.parse_args(argv)
    command = args.command or "summary"
    if command == "self-test":
        return self_test()
    if command == "mark":
        return cmd_mark()
    if command == "probe":
        return cmd_probe()
    section = "all" if command == "summary" else command
    if command == "summary":
        section = args.section
    require = bool(getattr(args, "require_email_code_verify", False))
    no_wait = bool(getattr(args, "no_wait", False))
    return analyze(section, wait=not no_wait, require_email_code=require)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
