// Synthetic camera captures of attendance QR codes, one family per failure
// mode seen in lecture halls. Every case is a 640x640 RGBA frame — the same
// window scan.html's decodeCrop() hands to the decoder — rendered from a real
// payload shape (an MCV self-check URL or a ClassDeeDee {sid, n} JSON) and then
// pushed through the degradation for its family.
//
// Everything is seeded, so a given seed always produces the same images and a
// before/after comparison is apples to apples.

const QRCode = require('qrcode');
const jpeg = require('jpeg-js');

const N = 640;

function rng(seed) {
  // mulberry32
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const between = (r, lo, hi) => lo + (hi - lo) * r();
const pick = (r, xs) => xs[Math.floor(r() * xs.length)];
function gauss(r) {
  let u = 0, v = 0;
  while (u === 0) u = r();
  while (v === 0) v = r();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const str = (r, alphabet, n) => Array.from({ length: n }, () => pick(r, alphabet)).join('');

function payload(r) {
  if (r() < 0.5) {
    const course = 10000 + Math.floor(r() * 90000);
    const sess = 100000 + Math.floor(r() * 900000);
    return `https://www.mycourseville.com/?q=courseville/course/${course}/attendance_qr_selfcheck/${sess}/${str(r, ALNUM, 12)}`;
  }
  const sid = `${str(r, HEX, 8)}-${str(r, HEX, 4)}-${str(r, HEX, 4)}-${str(r, HEX, 4)}-${str(r, HEX, 12)}`;
  return JSON.stringify({ sid, n: str(r, ALNUM, 16) });
}

// Solve the 3x3 homography taking the unit square onto four image corners.
function homography(pts) {
  const [[x0, y0], [x1, y1], [x2, y2], [x3, y3]] = pts;
  const dx1 = x1 - x2, dx2 = x3 - x2, dx3 = x0 - x1 + x2 - x3;
  const dy1 = y1 - y2, dy2 = y3 - y2, dy3 = y0 - y1 + y2 - y3;
  const den = dx1 * dy2 - dx2 * dy1;
  const g = (dx3 * dy2 - dx2 * dy3) / den;
  const h = (dx1 * dy3 - dx3 * dy1) / den;
  return [x1 - x0 + g * x1, x3 - x0 + h * x3, x0,
          y1 - y0 + g * y1, y3 - y0 + h * y3, y0, g, h, 1];
}

function invert3(m) {
  const [a, b, c, d, e, f, g, h, i] = m;
  const A = e * i - f * h, B = -(d * i - f * g), C = d * h - e * g;
  const det = a * A + b * B + c * C;
  return [A / det, -(b * i - c * h) / det, (b * f - c * e) / det,
          B / det, (a * i - c * g) / det, -(a * f - c * d) / det,
          C / det, -(a * h - b * g) / det, (a * e - b * d) / det];
}

// Render the symbol (with its 4-module quiet zone) under a perspective
// transform, 3x3 supersampled so module edges are anti-aliased the way a lens
// would leave them. Returns per-pixel "ink" coverage in [0,1].
function renderInk(text, r, sizePx) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const mods = qr.modules.size, total = mods + 8;
  const cx = N / 2 + between(r, -40, 40), cy = N / 2 + between(r, -40, 40);
  const rot = between(r, -0.35, 0.35);
  const half = sizePx / 2;
  const corners = [[-1, -1], [1, -1], [1, 1], [-1, 1]].map(([u, v]) => {
    // Up to ~12% keystone, like holding a phone below a projector screen.
    const ju = u * half * (1 + between(r, -0.12, 0.12));
    const jv = v * half * (1 + between(r, -0.12, 0.12));
    return [cx + ju * Math.cos(rot) - jv * Math.sin(rot),
            cy + ju * Math.sin(rot) + jv * Math.cos(rot)];
  });
  const Hinv = invert3(homography(corners));
  const ink = new Float32Array(N * N);
  const S = 3;
  for (let y = 0; y < N; y++) {
    for (let x = 0; x < N; x++) {
      let acc = 0, inside = false;
      for (let sy = 0; sy < S; sy++) {
        for (let sx = 0; sx < S; sx++) {
          const px = x + (sx + 0.5) / S, py = y + (sy + 0.5) / S;
          const w = Hinv[6] * px + Hinv[7] * py + Hinv[8];
          const u = (Hinv[0] * px + Hinv[1] * py + Hinv[2]) / w;
          const v = (Hinv[3] * px + Hinv[4] * py + Hinv[5]) / w;
          if (u < 0 || u >= 1 || v < 0 || v >= 1) continue;
          inside = true;
          const col = Math.floor(u * total) - 4, row = Math.floor(v * total) - 4;
          if (col >= 0 && row >= 0 && col < mods && row < mods && qr.modules.get(row, col)) acc++;
        }
      }
      ink[y * N + x] = inside ? acc / (S * S) : -1;   // -1 = off the slide
    }
  }
  return ink;
}

// ---- image ops on Float32 RGB planes ----------------------------------------

function paint(ink, dark, light, surround) {
  const img = [new Float32Array(N * N), new Float32Array(N * N), new Float32Array(N * N)];
  for (let i = 0; i < N * N; i++) {
    for (let c = 0; c < 3; c++) {
      img[c][i] = ink[i] < 0 ? surround[c] : light[c] + (dark[c] - light[c]) * ink[i];
    }
  }
  return img;
}

function gaussianBlur(img, sigma) {
  if (sigma <= 0) return img;
  const rad = Math.ceil(sigma * 3), k = [];
  let sum = 0;
  for (let i = -rad; i <= rad; i++) { const v = Math.exp(-(i * i) / (2 * sigma * sigma)); k.push(v); sum += v; }
  for (let i = 0; i < k.length; i++) k[i] /= sum;
  return img.map((p) => {
    const tmp = new Float32Array(N * N), out = new Float32Array(N * N);
    for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
      let a = 0;
      for (let i = -rad; i <= rad; i++) a += p[y * N + Math.min(N - 1, Math.max(0, x + i))] * k[i + rad];
      tmp[y * N + x] = a;
    }
    for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
      let a = 0;
      for (let i = -rad; i <= rad; i++) a += tmp[Math.min(N - 1, Math.max(0, y + i)) * N + x] * k[i + rad];
      out[y * N + x] = a;
    }
    return out;
  });
}

// Directional smear — the phone moving while the shutter is open.
function motionBlur(img, len, angle) {
  const dx = Math.cos(angle), dy = Math.sin(angle), steps = Math.max(2, Math.round(len));
  return img.map((p) => {
    const out = new Float32Array(N * N);
    for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
      let a = 0;
      for (let s = 0; s < steps; s++) {
        const t = s / (steps - 1) - 0.5;
        const sx = Math.min(N - 1, Math.max(0, Math.round(x + dx * t * len)));
        const sy = Math.min(N - 1, Math.max(0, Math.round(y + dy * t * len)));
        a += p[sy * N + sx];
      }
      out[y * N + x] = a / steps;
    }
    return out;
  });
}

function addNoise(img, r, sigma, chroma) {
  for (let i = 0; i < N * N; i++) {
    const l = gauss(r) * sigma;
    for (let c = 0; c < 3; c++) img[c][i] += l + (chroma ? gauss(r) * chroma : 0);
  }
  return img;
}

// Soft hotspot — a ceiling light or the projector lamp reflecting off a
// glossy screen, washing part of the code toward white.
function addGlare(img, r, strength) {
  const gx = between(r, 0.2, 0.8) * N, gy = between(r, 0.2, 0.8) * N;
  const rad = between(r, 0.18, 0.4) * N;
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    const d2 = ((x - gx) ** 2 + (y - gy) ** 2) / (rad * rad);
    const g = strength * Math.exp(-d2);
    const i = y * N + x;
    for (let c = 0; c < 3; c++) img[c][i] = img[c][i] + (255 - img[c][i]) * g;
  }
  return img;
}

// Uneven lighting across the whole frame: one side of the slide in shadow.
function addGradient(img, r, depth) {
  const a = between(r, 0, Math.PI * 2), ca = Math.cos(a), sa = Math.sin(a);
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    const t = ((x - N / 2) * ca + (y - N / 2) * sa) / N + 0.5;   // ~0..1
    const f = 1 - depth * Math.min(1, Math.max(0, t));
    const i = y * N + x;
    for (let c = 0; c < 3; c++) img[c][i] *= f;
  }
  return img;
}

// Photographing an LCD or projected image: the screen's pixel grid beats
// against the sensor's, leaving low-frequency bands across the code, plus
// the fine RGB subpixel stripe.
function addMoire(img, r, amp) {
  const waves = [0, 1].map(() => {
    const period = between(r, 5, 22), ang = between(r, 0, Math.PI);
    return [Math.cos(ang) * 2 * Math.PI / period, Math.sin(ang) * 2 * Math.PI / period, between(r, 0, 6.28)];
  });
  for (let y = 0; y < N; y++) for (let x = 0; x < N; x++) {
    let m = 0;
    for (const [fx, fy, ph] of waves) m += Math.cos(fx * x + fy * y + ph);
    const f = 1 - amp * (0.5 + 0.25 * m);
    const i = y * N + x;
    for (let c = 0; c < 3; c++) {
      const sub = (x % 3 === c) ? 1 : 1 - amp * 0.5;
      img[c][i] *= f * sub;
    }
  }
  return img;
}

function toRGBA(img) {
  const out = new Uint8ClampedArray(N * N * 4);
  for (let i = 0; i < N * N; i++) {
    out[i * 4] = img[0][i]; out[i * 4 + 1] = img[1][i]; out[i * 4 + 2] = img[2][i]; out[i * 4 + 3] = 255;
  }
  return out;
}

function jpegRoundTrip(rgba, quality) {
  const enc = jpeg.encode({ data: Buffer.from(rgba.buffer), width: N, height: N }, quality);
  const dec = jpeg.decode(enc.data, { useTArray: true, formatAsRGBA: true });
  return new Uint8ClampedArray(dec.data.buffer, dec.data.byteOffset, dec.data.length);
}

// ---- families ---------------------------------------------------------------

const grey = (v) => [v, v, v];
const tint = (r, v, spread) => [v + between(r, -spread, spread), v + between(r, -spread, spread), v + between(r, -spread, spread)];

// Module sizes from "far back of the hall" to "arm's length". An MCV URL is a
// version-5 symbol (45 modules with the quiet zone), so 170px is ~3.8px/module.
const sizeFor = (r) => pick(r, [170, 220, 280, 360, 460]);

const FAMILIES = {
  clean(r) {
    return { dark: grey(25), light: grey(235), surround: grey(200), blur: 0.6, noise: 3, jpeg: 85 };
  },
  // A grey code: a light-grey QR on a white slide, or a projector whose
  // black level is nowhere near black. Contrast between modules is 25-70
  // levels out of 255.
  grey(r) {
    const light = between(r, 190, 235), gap = between(r, 25, 70);
    return { dark: grey(light - gap), light: grey(light), surround: grey(light - 10),
             blur: between(r, 0.6, 1.2), noise: between(r, 3, 7), jpeg: 80 };
  },
  // Overexposed: the camera meters for the dark room, so a bright projected
  // code clips toward white and its modules come out a pale grey.
  washed_out(r) {
    const dark = between(r, 185, 225);
    return { dark: grey(dark), light: grey(255), surround: grey(between(r, 90, 160)),
             blur: between(r, 0.8, 1.5), noise: between(r, 2, 5), jpeg: 75 };
  },
  // Underexposed dim room: everything crushed into the bottom of the range.
  dark(r) {
    const light = between(r, 55, 90), dark = light - between(r, 18, 40);
    return { dark: grey(dark), light: grey(light), surround: grey(light * 0.7),
             blur: between(r, 0.8, 1.4), noise: between(r, 4, 9), chroma: 3, jpeg: 70 };
  },
  // Low-light grain: the phone's sensor at high ISO.
  noisy(r) {
    const light = between(r, 150, 220), gap = between(r, 60, 120);
    return { dark: grey(light - gap), light: grey(light), surround: grey(light - 20),
             blur: between(r, 0.6, 1.0), noise: between(r, 18, 32), chroma: between(r, 4, 10), jpeg: 70 };
  },
  glare(r) {
    return { dark: grey(between(r, 30, 80)), light: grey(between(r, 190, 230)), surround: grey(170),
             blur: between(r, 0.6, 1.2), noise: between(r, 3, 6), glare: between(r, 0.65, 0.92), jpeg: 80 };
  },
  uneven_light(r) {
    return { dark: grey(between(r, 30, 70)), light: grey(between(r, 180, 230)), surround: grey(160),
             blur: between(r, 0.6, 1.2), noise: between(r, 3, 6), gradient: between(r, 0.55, 0.8), jpeg: 80 };
  },
  // Out of focus — the phone focusing on the desk or the person in front.
  defocus(r) {
    return { dark: grey(between(r, 30, 70)), light: grey(between(r, 190, 230)), surround: grey(180),
             blur: between(r, 1.8, 3.2), noise: between(r, 2, 5), jpeg: 80 };
  },
  motion(r) {
    return { dark: grey(between(r, 30, 70)), light: grey(between(r, 190, 230)), surround: grey(180),
             blur: 0.7, motion: [between(r, 4, 9), between(r, 0, Math.PI)], noise: between(r, 3, 6), jpeg: 80 };
  },
  moire(r) {
    const light = between(r, 170, 225);
    return { dark: grey(light - between(r, 70, 130)), light: tint(r, light, 12), surround: grey(light - 30),
             blur: between(r, 0.5, 0.9), noise: between(r, 4, 8), moire: between(r, 0.25, 0.45), jpeg: 70 };
  },
  // Heavy compression — a frame that went through a low-quality encode, or a
  // photo of the code forwarded through a chat app.
  jpeg_blocky(r) {
    const light = between(r, 170, 225);
    return { dark: grey(light - between(r, 50, 110)), light: grey(light), surround: grey(light - 15),
             blur: between(r, 0.8, 1.3), noise: between(r, 4, 8), jpeg: Math.round(between(r, 8, 20)) };
  },
  // What actually shows up in a lecture hall: several of the above at once.
  combined(r) {
    const light = between(r, 150, 225), gap = between(r, 35, 80);
    return { dark: grey(light - gap), light: tint(r, light, 8), surround: grey(light - 25),
             blur: between(r, 0.9, 1.8), noise: between(r, 7, 14), chroma: 4,
             glare: r() < 0.5 ? between(r, 0.3, 0.6) : 0,
             moire: r() < 0.5 ? between(r, 0.12, 0.25) : 0,
             gradient: r() < 0.5 ? between(r, 0.2, 0.45) : 0,
             jpeg: Math.round(between(r, 25, 55)) };
  },
};

function makeCase(family, seed) {
  const r = rng(seed);
  const text = payload(r);
  const size = sizeFor(r);
  const p = FAMILIES[family](r);
  const ink = renderInk(text, r, size);
  let img = paint(ink, p.dark, p.light, p.surround);
  if (p.gradient) img = addGradient(img, r, p.gradient);
  if (p.moire) img = addMoire(img, r, p.moire);
  if (p.glare) img = addGlare(img, r, p.glare);
  img = gaussianBlur(img, p.blur);
  if (p.motion) img = motionBlur(img, p.motion[0], p.motion[1]);
  img = addNoise(img, r, p.noise, p.chroma || 0);
  let rgba = toRGBA(img);
  if (p.jpeg) rgba = jpegRoundTrip(rgba, p.jpeg);
  return { family, seed, text, size, width: N, height: N, data: rgba };
}

module.exports = { FAMILIES: Object.keys(FAMILIES), makeCase, N };
