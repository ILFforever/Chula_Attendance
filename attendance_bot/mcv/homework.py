"""MyCourseVille homework/assignment check.

One authenticated call covers every enrolled course at once — MCV's homepage
loads its own "due soon" panel via this same AJAX endpoint, so there's no
need to loop per-subject the way ClassDeeDee requires (see
classdeedee/homework.py's docstring for why that one can't be a single call).

    POST https://www.mycourseville.com/?q=courseville/ajax/getactivepanelcontent
    Headers: X-Requested-With: XMLHttpRequest
    -> {"status": 1, "count": N, "html": "<div class=\"cv-item\">...</div>..."}

`html` is a fragment, not clean JSON — items are `<div class="cv-item">`
blocks; the first one is a summary line ("N items due in 7 days") with no
worksheet link and gets skipped. Confirmed against a working reference
implementation (Google Apps Script) that hits this same endpoint.
"""
from __future__ import annotations

import re

import requests as http_requests

from attendance_bot.config import log
from attendance_bot.mcv.attendance import REQUEST_TIMEOUT, fetch_public_course_info

MCV_PANEL_URL = "https://www.mycourseville.com/?q=courseville/ajax/getactivepanelcontent"
MCV_COURSE_URL = "https://www.mycourseville.com/?q=courseville/course/{course_id}"

_LINK_RE = re.compile(r'href="([^"]*\?q=courseville/worksheet/[^"]+)"')
_BADGE_RE = re.compile(r'cvui-course-badge">([^<]+)<')
_TITLE_RE = re.compile(r'<strong>(?:&ldquo;|["“])?([^<]*?)(?:&rdquo;|["”])?</strong>')
_DUE_RE = re.compile(r'du\w*\s+in\s*<strong>([^<]+)</strong>', re.IGNORECASE)

# Internal MCV course id embedded in a worksheet link's path, e.g.
# .../worksheet/85196/2154933 -> 85196. Used to look up the course's public
# name (worksheet pages themselves carry no og:title; the course home page does).
_WORKSHEET_COURSE_ID_RE = re.compile(r"/worksheet/(\d+)/")
_WORKSHEET_ITEM_ID_RE = re.compile(r"/worksheet/\d+/(\d+)")

# The public og:title looks like "2110506 (2026/1) Software-Defined Systems I
# [Section 51 - 55]" — strip the code/term prefix and section suffix down to
# just the human-readable name.
_TITLE_CLEAN_RE = re.compile(r"^\d+\s*\([^)]*\)\s*(.*?)\s*(?:\[.*\])?$")


def _clean_course_name(raw_title: str) -> str:
    m = _TITLE_CLEAN_RE.match(raw_title)
    return m.group(1).strip() if m and m.group(1).strip() else raw_title


def fetch_upcoming_items(session: http_requests.Session) -> list[dict]:
    """Return every pending item across all of this user's MCV courses.

    Each item: {course_code, course_name, title, due, link}. `due` is MCV's
    own display string (e.g. "3 days") — there's no machine-readable deadline
    in this panel, only relative wording. `course_name` is looked up
    separately (one request per distinct course) since the panel itself only
    carries the course code badge.
    """
    r = session.post(
        MCV_PANEL_URL,
        headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json, text/javascript, */*; q=0.01"},
        timeout=REQUEST_TIMEOUT,
    )
    if not r.ok:
        log.warning("MCV upcoming-items panel failed (HTTP %d)", r.status_code)
        return []
    try:
        data = r.json()
    except ValueError:
        log.warning("MCV upcoming-items panel response was not JSON")
        return []

    if data.get("status") != 1 or not data.get("html"):
        return []

    items = _parse_panel_html(data["html"])
    _backfill_course_names(items)
    return items


def _backfill_course_names(items: list[dict]) -> None:
    """Mutates `items` in place, adding a best-effort `course_name`."""
    name_by_internal_id: dict[str, str | None] = {}
    for item in items:
        m = _WORKSHEET_COURSE_ID_RE.search(item["link"])
        internal_id = m.group(1) if m else None
        item["_internal_id"] = internal_id
        if internal_id and internal_id not in name_by_internal_id:
            name_by_internal_id[internal_id] = None  # reserve, fetch below

    for internal_id in name_by_internal_id:
        info = fetch_public_course_info(MCV_COURSE_URL.format(course_id=internal_id))
        name_by_internal_id[internal_id] = _clean_course_name(info["title"]) if info else None

    for item in items:
        internal_id = item.pop("_internal_id")
        item["course_name"] = name_by_internal_id.get(internal_id)


def _parse_panel_html(html: str) -> list[dict]:
    blocks = html.split('<div class="cv-item">')[1:]  # drop the summary line before the first item
    items = []
    for block in blocks:
        link_match = _LINK_RE.search(block)
        if not link_match:
            continue  # summary line / no-link block

        link = link_match.group(1)
        if not link.startswith("http"):
            link = "https://www.mycourseville.com/" + link.lstrip("/")

        badge_match = _BADGE_RE.search(block)
        title_match = _TITLE_RE.search(block)
        due_match = _DUE_RE.search(block)

        item_id_match = _WORKSHEET_ITEM_ID_RE.search(link)

        items.append({
            "course_code": badge_match.group(1).strip() if badge_match else "",
            "title": title_match.group(1).strip() if title_match else "Untitled item",
            "due": due_match.group(1).strip() if due_match else "",
            "link": link,
            # Stable per-item id for the "handed in" suppression store — MCV
            # gives no other identifier, so the worksheet link's own path is it.
            "item_key": item_id_match.group(1) if item_id_match else link,
        })
    return items


def items_for_subjects(items: list[dict], subjects: list[str]) -> list[dict]:
    """Filter upcoming items by a user's `/enroll` subjects.

    Empty `subjects` returns everything — same semantics as MCV check-in
    filtering and ClassDeeDee's courses_for_subjects().
    """
    if not subjects:
        return items
    return [item for item in items if item["course_code"] in subjects]
