# ClassDeeDee check-in: what actually gets sent, and the course-scoping question

Notes from reverse-engineering the real ClassDeeDee frontend, to answer: *does
our bot's check-in need to know which course a QR belongs to?*

## What the bot sends

[`attendance_bot/classdeedee/attendance.py`](../attendance_bot/classdeedee/attendance.py) has the bot POST the
scanned QR's contents straight to ClassDeeDee's own API, authenticated as the
student (via the ChulaSSO session from [`attendance_bot/classdeedee/login.py`](../attendance_bot/classdeedee/login.py)):

```
POST https://classdeedee.cloud.cp.eng.chula.ac.th/api/attendants/checkin
Content-Type: application/json

{"sessionid": "<sid from QR>", "nonce": "<n from QR>"}
```

No course identifier is sent. `check_in_all(sid, nonce)` has no `course_id`
parameter at all — it just runs every registered user with a usable
ClassDeeDee credential (`resolve_cdd_credentials`) against this one endpoint,
unconditionally. This is unlike the MyCourseVille path (`attendance_bot/mcv/attendance.py`),
which filters by the `subjects` list a user sets with `/enroll` before
checking them in.

## Confirmed against the real client

The checkin page (`https://classdeedee.cloud.cp.eng.chula.ac.th/courses/<courseid>/checkin`)
is a Next.js static export. Its page-specific JS bundle
(`checkin-<hash>.js`) shows the QR scan handler and the API call it makes:

```js
// QR scan handler
if (!n || !n.sid || !n.n) {
  w({status: "error", info: "That is not an attendance QR code"});
  return;
}
submit(n.sid, n.n);

// submit()
submit = function (e, t) {
  h.Z.checkin(e, t, successCb, errorCb);
};

// the API client (baseURL = "/api/attendants/")
u.checkin = function (e, t, n, a, o) {
  var i = u.baseURL + "checkin";
  return r.Z.post(i, { sessionid: e, nonce: t }, n, a, o);
};
```

So the real app's request body is exactly `{sessionid, nonce}` — a 1:1 match
with what the bot already sends. The page does read `courseid` out of its own
URL (`n.query.courseid`), but that value is only used for the page's own
routing/display — it is **never** included in the `checkin` POST.

There's a second, separate endpoint in the same API module,
`attendByQR(courseid, qr_text)` → `POST /api/attendants/attendByQR` with
`{courseid, qr_text}`, which *does* carry a course id. The checkin page does
not call it, though — the QR-scan flow only ever calls `checkin(sid, nonce)`.
Its role (manual/legacy self-attend?) is unconfirmed and out of scope here.

## What this means

Since the real client never tells the server which course it thinks it's
scanning for, any course enforcement can only happen server-side, keyed off
`sessionid` alone (presumably `sessionid` is already scoped to one course's
session when the instructor's QR is generated). This can't be verified from
the frontend code — it depends entirely on how ClassDeeDee's backend treats
`sessionid` for a user who isn't enrolled in that session's course.

The bot already handles an unknown/rejection response gracefully — anything
other than `info == "checked_in"`/`"already"` falls through to a generic
warning line in `check_in_one()`:

```python
detail = data.get("info") or f"HTTP {r.status_code}"
return f"⚠️ **[{name}]** — {detail}"
```

So a non-enrolled user would not be falsely reported as checked in — but we
don't yet know the exact rejection string ClassDeeDee would return for that
case, so there's no dedicated, friendly message for it today (unlike MCV's
explicit `🚫 not a course member` handling in `attendance_bot/mcv/attendance.py`).

## Still open

- Confirm empirically what `info` value ClassDeeDee returns when a
  registered-but-not-enrolled user's session hits `/api/attendants/checkin`
  for a course they aren't in. Needs either a live test QR or Fly logs from a
  real mismatched check-in.
- If/when that string is known, add an explicit branch for it in
  `check_in_one()` (mirroring MCV's `🚫` handling) instead of the generic
  `⚠️ {detail}` fallback.
