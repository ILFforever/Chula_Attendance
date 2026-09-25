# QR scan benchmark

Before/after benchmark for the web scanner's decode (`web/scan.html` +
`web/qrenhance.js`). It is not part of the bot and is not deployed.

```bash
cd bench/qr
npm install
npm run bench                      # 12 families x 30 synthetic cases (~2 min)
npm run bench -- --family grey,noisy --n 60
npm run bench -- --real ~/qr-photos/   # your own .jpg/.png phone captures
```

**Synthetic suite** (`cases.js`): real payload shapes (MCV self-check URLs,
ClassDeeDee `{sid, n}` JSON) rendered at lecture-hall distances with
perspective, then degraded one way per family: grey, washed-out, dark, noisy,
glare, uneven light, defocus, motion, moiré, heavy JPEG, and a combination.
Seeds are fixed. Tuning used seeds 1000+ and the default report uses 5000+,
so the headline numbers come from cases the settings weren't fitted to.

**Real photos**: each image is treated as a camera frame and decoded through
both windows the page uses (the reticle crop and the full frame). A decode
counts only if it's a valid attendance payload. Photos of the codes that fail
in class are the best test there is. Add them here.

"before" is the raw crop into jsQR, which is what the page did before
`qrenhance.js`. "after" is the rotation the page runs now. `bench.js` mirrors
the passes in `scan.html`'s `tick()`, so change them together.
