import re

import requests as http_requests
from bs4 import BeautifulSoup

from attendance_bot.config import log

COURSE_URL = "https://cugetreg.com/S/courses/{course_id}"
REQUEST_TIMEOUT = 15
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def fetch_course_name(course_id: str) -> dict | None:
    """Look up a course's name on CU Get Reg by its course code.

    Returns {"code", "name_short", "name_th", "name_en"}, or None if the
    course isn't found or the lookup fails (e.g. site down, network error).
    """
    try:
        resp = http_requests.get(
            COURSE_URL.format(course_id=course_id),
            headers={"User-Agent": _USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
    except http_requests.RequestException as exc:
        log.warning("CU Get Reg lookup failed for %s: %s", course_id, exc)
        return None

    if resp.status_code != 200:
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    h3 = soup.find(class_=lambda c: c and "MuiTypography-h3" in c)
    if not h3:
        return None

    h3_text = h3.get_text(strip=True)
    match = re.match(r"(\d+)\s*(.*)", h3_text)
    code, name_short = (match.group(1), match.group(2)) if match else (course_id, h3_text)

    h5s = soup.find_all(class_=lambda c: c and "MuiTypography-h5" in c)
    name_th = h5s[0].get_text(strip=True) if len(h5s) > 0 else ""
    name_en = h5s[1].get_text(strip=True) if len(h5s) > 1 else name_short

    return {
        "code": code,
        "name_short": name_short,
        "name_th": name_th,
        "name_en": name_en,
    }
