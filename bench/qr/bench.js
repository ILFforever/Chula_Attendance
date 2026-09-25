#!/usr/bin/env node
// Before/after benchmark for the scanner's QR decode (web/scan.html).
//
//   npm run bench                     synthetic suite, 30 cases per family
//   npm run bench -- --n 60           more cases per family
//   npm run bench -- --seed 1000      a different set of cases
//   npm run bench -- --real photos/   your own phone photos (.jpg/.png)
//
// "before" is what scan.html did on the jsQR path until now: the raw crop,
// straight into jsQR. "after" is the passes the scan loop now rotates through
// on the same crop. The loop runs each pass on consecutive frames, a few ms
// apart, so a case counts as decoded if any pass in the rotation reads it.
// A decode that returns the wrong text counts as a failure, and is also
// reported on its own line.

const fs = require('fs');
const path = require('path');
const jpeg = require('jpeg-js');
const { PNG } = require('pngjs');
const jsQR = require('../../web/jsQR.js');
const QREnhance = require('../../web/qrenhance.js');
const { FAMILIES, makeCase } = require('./cases.js');

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf('--' + name);
  return i === -1 ? dflt : args[i + 1];
};

// Mirrors the crop passes in scan.html's tick(): the raw crop, then the crop
// binarized with and without a blur pass. Keep these in step with the page.
// (The page also rotates in a full-frame pass, which targets a code held off
// to the side of the reticle. Every synthetic case sits inside the crop, so
// the synthetic suite leaves it out. --real runs it.)
const decode = (d, w, h) => jsQR(d, w, h, { inversionAttempts: 'dontInvert' });
const PASSES = {
  raw: (d, w, h) => decode(d, w, h),
  blur: (d, w, h) => decode(QREnhance.binarize(d, w, h, 1), w, h),
  sharp: (d, w, h) => decode(QREnhance.binarize(d, w, h, 0), w, h),
};
const PIPELINES = {
  before: ['raw'],
  after: ['raw', 'blur', 'sharp'],
};

function run(pipeline, img, expect) {
  let hit = null, wrong = false;
  const passes = {};
  for (const name of PIPELINES[pipeline]) {
    const t = process.hrtime.bigint();
    let res = null;
    try { res = PASSES[name](img.data, img.width, img.height); } catch (e) { res = null; }
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    const ok = !!res && expect(res.data);
    if (res && !ok) wrong = true;
    passes[name] = { ok, ms };
    if (ok && !hit) hit = name;
  }
  return { hit, wrong, passes };
}

const pct = (a, b) => (b ? (100 * a / b).toFixed(0).padStart(3) + '%' : '   -');

function report(rows, groups) {
  const tot = { before: 0, after: 0, n: 0, wb: 0, wa: 0 };
  console.log('\n' + 'family'.padEnd(16) + 'before'.padStart(12) + 'after'.padStart(12) + '   change');
  console.log('-'.repeat(50));
  for (const g of groups) {
    const rs = rows.filter((r) => r.group === g);
    const b = rs.filter((r) => r.before.hit).length, a = rs.filter((r) => r.after.hit).length;
    tot.before += b; tot.after += a; tot.n += rs.length;
    tot.wb += rs.filter((r) => r.before.wrong).length; tot.wa += rs.filter((r) => r.after.wrong).length;
    const d = a - b;
    console.log(g.padEnd(16) + `${String(b).padStart(3)}/${rs.length} ${pct(b, rs.length)}` +
      `${String(a).padStart(4)}/${rs.length} ${pct(a, rs.length)}` + `   ${d > 0 ? '+' : ''}${d}`);
  }
  console.log('-'.repeat(50));
  console.log('TOTAL'.padEnd(16) + `${String(tot.before).padStart(3)}/${tot.n} ${pct(tot.before, tot.n)}` +
    `${String(tot.after).padStart(4)}/${tot.n} ${pct(tot.after, tot.n)}` + `   +${tot.after - tot.before}`);
  const regress = rows.filter((r) => r.before.hit && !r.after.hit);
  console.log(`\nregressions (before read it, after did not): ${regress.length}`);
  regress.forEach((r) => console.log('  ' + r.id));
  console.log(`wrong decodes: before ${tot.wb}, after ${tot.wa}`);

  console.log('\nper pass            hit rate   mean ms   p95 ms');
  for (const name of PIPELINES.after) {
    const ms = rows.map((r) => r.after.passes[name].ms).sort((x, y) => x - y);
    const hits = rows.filter((r) => r.after.passes[name].ok).length;
    const mean = ms.reduce((s, v) => s + v, 0) / ms.length;
    console.log(`  ${name.padEnd(16)} ${pct(hits, rows.length).padStart(8)} ${mean.toFixed(1).padStart(9)} ${ms[Math.floor(ms.length * 0.95)].toFixed(1).padStart(8)}`);
  }
  const only = rows.filter((r) => r.after.hit && !r.after.passes.raw.ok).length;
  console.log(`  read only by a binarized pass: ${only}`);
}

function synthetic() {
  const n = Number(opt('n', 30)), seed = Number(opt('seed', 5000));
  const only = opt('family', null);
  const fams = only ? only.split(',') : FAMILIES;
  console.log(`synthetic suite: ${fams.length} families x ${n} cases, seeds ${seed}..${seed + n - 1}`);
  const rows = [];
  for (const f of fams) {
    for (let i = 0; i < n; i++) {
      const c = makeCase(f, seed + i);
      const expect = (t) => t === c.text;
      rows.push({ group: f, id: `${f} seed=${seed + i} size=${c.size}`,
                  before: run('before', c, expect), after: run('after', c, expect) });
    }
    process.stderr.write('.');
  }
  process.stderr.write('\n');
  report(rows, fams);
}

// ---- real photos ------------------------------------------------------------

const MCV = /https?:\/\/(?:www\.)?mycourseville\.com\/\?q=courseville\/course\/\d+\/attendance_qr_selfcheck\/\d+\/[A-Za-z0-9]+/;
function isAttendance(t) {
  if (MCV.test(t)) return true;
  try { const d = JSON.parse(t); return !!(d && d.sid && d.n); } catch (e) { return false; }
}

function load(file) {
  const buf = fs.readFileSync(file);
  if (/\.png$/i.test(file)) {
    const p = PNG.sync.read(buf);
    return { width: p.width, height: p.height, data: new Uint8ClampedArray(p.data) };
  }
  const j = jpeg.decode(buf, { useTArray: true, formatAsRGBA: true, maxMemoryUsageInMB: 1024 });
  return { width: j.width, height: j.height, data: new Uint8ClampedArray(j.data) };
}

// Area-average resample of a source rectangle to w x h — close to what a
// browser's drawImage does when it shrinks a video frame onto the canvas.
function resample(src, sx, sy, sw, sh, w, h) {
  const out = new Uint8ClampedArray(w * h * 4);
  for (let y = 0; y < h; y++) {
    const ya = Math.floor(sy + y * sh / h), yb = Math.max(ya + 1, Math.floor(sy + (y + 1) * sh / h));
    for (let x = 0; x < w; x++) {
      const xa = Math.floor(sx + x * sw / w), xb = Math.max(xa + 1, Math.floor(sx + (x + 1) * sw / w));
      let r = 0, g = 0, b = 0, n = 0;
      for (let yy = ya; yy < yb && yy < src.height; yy++) {
        for (let xx = xa; xx < xb && xx < src.width; xx++) {
          const p = (yy * src.width + xx) * 4;
          r += src.data[p]; g += src.data[p + 1]; b += src.data[p + 2]; n++;
        }
      }
      const o = (y * w + x) * 4;
      out[o] = r / n; out[o + 1] = g / n; out[o + 2] = b / n; out[o + 3] = 255;
    }
  }
  return { width: w, height: h, data: out };
}

// A photo is treated as a camera frame, scaled so its long side is 1920 like
// the stream scan.html asks for. It then goes through both windows the page
// decodes: the reticle crop and the whole frame at 480 wide.
function real(dir) {
  const files = fs.readdirSync(dir).filter((f) => /\.(jpe?g|png)$/i.test(f)).sort();
  if (!files.length) { console.log(`no .jpg/.png files in ${dir}`); return; }
  console.log(`real photos: ${files.length} from ${dir}`);
  const rows = [];
  for (const f of files) {
    let img = load(path.join(dir, f));
    const scale = 1920 / Math.max(img.width, img.height);
    if (scale < 1) img = resample(img, 0, 0, img.width, img.height,
                                  Math.round(img.width * scale), Math.round(img.height * scale));
    const side = Math.min(img.width, img.height) * 0.64;
    const n = Math.min(640, Math.round(side));
    const crop = resample(img, (img.width - side) / 2, (img.height - side) / 2, side, side, n, n);
    const fw = 480, fh = Math.round(img.height * 480 / img.width);
    const full = resample(img, 0, 0, img.width, img.height, fw, fh);
    for (const [win, im] of [['crop', crop], ['full', full]]) {
      rows.push({ group: win, id: `${f} (${win})`,
                  before: run('before', im, isAttendance), after: run('after', im, isAttendance) });
    }
  }
  report(rows, ['crop', 'full']);
  console.log('\nper photo (either window):');
  for (const f of files) {
    const rs = rows.filter((r) => r.id.startsWith(f + ' '));
    const b = rs.some((r) => r.before.hit), a = rs.some((r) => r.after.hit);
    console.log(`  ${b ? 'OK  ' : 'fail'} -> ${a ? 'OK  ' : 'fail'}  ${f}`);
  }
}

const realDir = opt('real', null);
if (realDir) real(realDir); else synthetic();
