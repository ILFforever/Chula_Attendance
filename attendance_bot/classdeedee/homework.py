"""ClassDeeDee homework/assignment check.

Two calls per user, both authenticated via the same session `login.py` already
produces for check-in:

  1. GET  /api/courses/me
        → every course the user is enrolled in this term. ClassDeeDee's own
          `courseid` (e.g. "2026S12110413CEDT") is an internal ID unrelated to
          the public course code — but `description` is rendered client-side
          as "<public_code> - <name>" (confirmed from the "My Courses" page's
          rendered DOM + its index-*.js bundle), so the public code can be
          recovered from it. This mirrors how MCV's course code is recovered
          from a link's OpenGraph metadata rather than trusted from a
          platform-internal ID (see mcv/attendance.py).
  2. GET  /api/assignments/forSubmission?courseid=<courseid>
        → that course's assignments, each carrying `my_submission` (truthy if
          this user already submitted). No aggregate "all courses" endpoint
          exists for this one, unlike MCV's getactivepanelcontent — so it's
          called once per matched course.

Reference: a working Google Apps Script doing the same two calls (Downloads/
message (1).txt) confirmed both endpoints' shapes end-to-end.
"""
from __future__ import annotations

import re

import requests as http_requests

from attendance_bot.config import log
from attendance_bot.classdeedee.login import (
    CDD,
    REQUEST_TIMEOUT,
    login_classdeedee,
    LoginError,
)

CDD_MY_COURSES = f"{CDD}/api/courses/me"
CDD_ASSIGNMENTS = f"{CDD}/api/assignments/forSubmission"

# ClassDeeDee's course `description` is rendered as "<public_code> - <name>".
_CODE_RE = re.compile(r"^\s*(\d{6,7})\b")

# `coursename` carries a trailing department-code suffix straight from their
# API (e.g. "Computer Security - CEDT") — strip it for display, same idea as
# MCV's own course-name cleanup in mcv/homework.py's _clean_course_name().
_DEPT_SUFFIX_RE = re.compile(r"^(.*?)\s*-\s*[A-Z]{2,8}$")


def _clean_course_name(raw_name: str) -> str:
    m = _DEPT_SUFFIX_RE.match(raw_name)
    return m.group(1).strip() if m and m.group(1).strip() else raw_name


def fetch_my_courses(session: http_requests.Session) -> list[dict]:
    """Return every course the logged-in user is enrolled in this term.

    Each item: {courseid, coursename, code}. `code` is the public course code
    parsed out of `description`, or None if it doesn't match the expected
    "<code> - <name>" shape.
    """
    r = session.get(CDD_MY_COURSES, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
    if not r.ok:
        raise LoginError(f"Could not fetch course list (HTTP {r.status_code})")
    try:
        courses = r.json()
    except ValueError as exc:
        raise LoginError(f"Course list response was not JSON: {exc}") from exc
    if not isinstance(courses, list):
        raise LoginError("Course list response was not a JSON array")

    out = []
    for c in courses:
        desc = c.get("description") or ""
        m = _CODE_RE.match(desc)
        raw_name = c.get("coursename") or c.get("courseid", "")
        out.append({
            "courseid": c.get("courseid"),
            "coursename": _clean_course_name(raw_name),
            "code": m.group(1) if m else None,
        })
    return out


def courses_for_subjects(session: http_requests.Session, subjects: list[str]) -> list[dict]:
    """Courses to homework-check for one user, filtered by their `/enroll` subjects.

    Empty `subjects` checks every course the user is on — same "opt-in
    scoping" semantics as MCV check-in filtering (attendance_bot/mcv/attendance.py).
    A non-empty `subjects` list with no match on this platform simply yields
    nothing to check (no silent fallback to "everything").
    """
    courses = fetch_my_courses(session)
    if not subjects:
        return courses
    return [c for c in courses if c["code"] and c["code"] in subjects]


def fetch_assignments(session: http_requests.Session, courseid: str) -> list[dict]:
    """Return one course's assignments open for submission.

    Each item: {title, deadline, submitted, link}.
    """
    r = session.get(
        CDD_ASSIGNMENTS,
        params={"courseid": courseid},
        timeout=REQUEST_TIMEOUT,
        headers={"Accept": "application/json, text/plain, */*"},
    )
    if not r.ok:
        log.warning("ClassDeeDee assignments fetch failed for %s (HTTP %d)", courseid, r.status_code)
        return []
    try:
        items = r.json()
    except ValueError:
        log.warning("ClassDeeDee assignments response for %s was not JSON", courseid)
        return []
    if not isinstance(items, list):
        return []

    out = []
    for item in items:
        uuid = item.get("uuid") or item.get("id") or ""
        link = (
            f"{CDD}/courses/{courseid}/assignments/submission/{uuid}"
            if uuid else f"{CDD}/courses/{courseid}/assignments"
        )
        out.append({
            "uuid": uuid,
            "title": item.get("title") or item.get("name") or "Untitled Assignment",
            "deadline": item.get("deadline"),
            "submitted": bool(item.get("my_submission")),
            "link": link,
        })
    return out


def check_homework_for_user(username: str, password: str, subjects: list[str]) -> list[dict]:
    """Log in once, then loop the user's enrolled-filtered courses collecting
    not-yet-submitted assignments.

    Returns a list of {course, course_code, courseid, uuid, title, deadline,
    link} dicts (empty if nothing outstanding). Raises WrongCredentialsError/
    LoginError/RequestException on failure — same exception contract as
    check_in_one, left for the caller to turn into a friendly per-user message.
    """
    session = login_classdeedee(username, password)
    try:
        courses = courses_for_subjects(session, subjects)
        outstanding = []
        for course in courses:
            if not course["courseid"]:
                continue
            for a in fetch_assignments(session, course["courseid"]):
                if a["submitted"]:
                    continue
                outstanding.append({
                    "course": course["coursename"],
                    "course_code": course["code"],
                    "courseid": course["courseid"],
                    "uuid": a["uuid"],
                    "title": a["title"],
                    "deadline": a["deadline"],
                    "link": a["link"],
                })
        return outstanding
    finally:
        session.close()
