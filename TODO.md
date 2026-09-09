# TODO — nice to have

Scanner-page ideas that came out of the per-user-token pass. Nothing here is
blocking; ordered roughly by payoff per unit of work.

## Feedback while scanning

- [ ] **Haptics on a hit.** `navigator.vibrate(60)` the moment a QR decodes,
      before the POST goes out. You hold the phone up at a projector and watch
      the *screen* rather than the page, so the green reticle is easy to miss.
      iOS ignores `vibrate` entirely — pair it with a short WebAudio blip
      (a ~40ms oscillator burst), unlocked on the first user gesture.
- [ ] Elapsed-time counter while the check-in runs, so a slow login run doesn't
      read as a frozen page.
- [ ] `AbortController` timeout on the `/api/scan` fetch — a hung request
      currently strands the page with no way back but a reload.
- [ ] **Retry** button that resubmits the last decoded URL. Right now any
      failure calls `stop()`, kills the camera, and forces a re-aim — which is
      absurd for the transient 429 ("another scan is still processing").

## Richer results

- [ ] Render the summary instead of printing `body.message`: the payload already
      carries `course`, `attempted`, `succeeded` and `duplicate`
      (`process_attendance_link` in `attendance_bot/client.py`) and the page
      throws all of it away. Returning the per-user `results` list too would
      show *who* failed without switching to Discord.
- [ ] Local scan history in `localStorage` (last ~5, time + outcome), so someone
      can check "did I already scan this class?"

## Scanning reliability

Resolution, the reticle crop, the frame-driven loop, and zoom/lens switching are
done. What is left:

- [ ] Torch toggle via `track.applyConstraints({advanced:[{torch:true}]})` —
      same mechanism as the zoom control, and a dim lecture hall is the other
      half of why a projector code fails.
- [ ] Tap-to-focus (`focusMode: 'manual'` + `pointsOfInterest`) where supported.
- [ ] Pause on `visibilitychange` — switching apps leaves the camera and the
      decode loop running.
- [ ] Decode from a photo (`<input type="file" accept="image/*">`). People
      screenshot the projector and post it in the group chat constantly.
- [ ] Debounce an identical `rawValue` for a few seconds; after "Scan another"
      the same QR still in frame resubmits instantly.
- [ ] `navigator.wakeLock` so the screen doesn't sleep mid-hunt.
- [ ] Consider moving the jsQR pass to a Worker. On a *typical* frame the crop
      costs ~17ms (desktop; 3-5x that on a phone), but jsQR degrades badly on
      grainy low-light frames — uniform noise measures ~460ms — and that runs on
      the main thread. The alternating cheap full-frame pass hides most of it.
- [ ] Remember the chosen stop in `localStorage`; right now every reopen
      starts back at the default camera at 1x.

## Page weight and install

- [ ] Lazy-load `jsQR.js`. It is 257KB fetched synchronously on every load, but
      only needed when `BarcodeDetector` is missing (desktop Firefox, older
      iOS). Most phones would never fetch it.
- [ ] `manifest.webmanifest` + `apple-touch-icon` + `theme-color`. The footer
      already tells people to add the page to their home screen; without a
      manifest that produces a plain bookmark rather than a standalone app.

## Server-side

- [ ] Rate-limit `/api/scan` and `/api/me` per token and per IP — there is
      currently nothing in front of the signature check.
- [ ] Enforce a max token age. The `issued_at` field is already carried in the
      token for exactly this and is currently unused, so expiry can be turned on
      without a format change.
- [ ] CSP header on the scanner HTML.
- [ ] Consider dropping the client-side `MCV` regex in `web/scan.html`. It
      duplicates the server's and can only ever *reject* a valid code if MCV
      changes its URL shape — the server already validates.
- [ ] Retire the legacy shared-secret fallback in
      `attendance_bot/scanner/tokens.py` once everyone has re-run `/scanner`.
