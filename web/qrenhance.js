// Clean-up passes that run on a camera frame before it reaches the QR decoder.
//
// jsQR thresholds each 8x8 block against its neighbourhood average and only
// trusts a block whose brightness range exceeds 24 levels. Real frames break
// both halves of that. A plain wall or slide carries sensor grain wider than
// 24 levels, so the flat area around the code gets binarised into
// salt-and-pepper that buries the finder patterns. And a grey or washed-out
// code has too little contrast to stand out from that grain. The code is
// plainly visible to a person, but jsQR can't read it.
//
// binarize() does the thresholding itself, noise-aware: optionally smooth out the
// grain, measure how much of it is left, and only threshold where the local contrast
// clearly exceeds it. It hands the decoder pure black and white. Everything is
// done on reused buffers, since the scan loop runs it on every other frame.
//
// Shared by web/scan.html and bench/qr/bench.js so the benchmark measures the
// exact code that ships.
(function (root) {
  var grey = null, tmp = null, sum = null, sq = null, size = 0;

  function buffers(n) {
    if (n === size) return;
    size = n;
    grey = new Float32Array(n);
    tmp = new Float32Array(n);
  }

  // Luma, then optionally a 3x3 box blur in each direction.
  function smooth(data, w, h, blur) {
    buffers(w * h);
    for (var i = 0, p = 0; i < w * h; i++, p += 4) {
      grey[i] = 0.2126 * data[p] + 0.7152 * data[p + 1] + 0.0722 * data[p + 2];
    }
    for (var pass = 0; pass < blur; pass++) {
      for (var y = 0; y < h; y++) {
        var row = y * w;
        for (var x = 0; x < w; x++) {
          var l = x > 0 ? x - 1 : 0, r = x < w - 1 ? x + 1 : x;
          tmp[row + x] = (grey[row + l] + grey[row + x] + grey[row + r]) / 3;
        }
      }
      for (var y2 = 0; y2 < h; y2++) {
        var up = (y2 > 0 ? y2 - 1 : 0) * w, dn = (y2 < h - 1 ? y2 + 1 : y2) * w, at = y2 * w;
        for (var x2 = 0; x2 < w; x2++) {
          grey[at + x2] = (tmp[up + x2] + tmp[at + x2] + tmp[dn + x2]) / 3;
        }
      }
    }
  }

  // Grain left after smoothing, from the median step between horizontal
  // neighbours. Most pixels sit inside a flat area or a module, so the median
  // step measures noise rather than edges. For Gaussian noise
  // median(|a-b|) = 0.954 * sigma.
  var hist = new Uint32Array(256);
  function noiseSigma(w, h) {
    hist.fill(0);
    var n = 0;
    for (var y = 0; y < h; y += 2) {
      var row = y * w;
      for (var x = 0; x < w - 1; x += 2) {
        var d = grey[row + x] - grey[row + x + 1];
        hist[Math.min(255, Math.round(d < 0 ? -d : d))]++;
        n++;
      }
    }
    var half = n / 2, acc = 0;
    for (var v = 0; v < 256; v++) {
      acc += hist[v];
      if (acc >= half) return Math.max(0.5, v / 0.954);
    }
    return 255;
  }

  // Local-mean threshold over a window a few modules wide, computed from
  // integral images so it costs the same whatever the window size. A window
  // whose spread is within a few noise sigmas of flat is white, not a coin
  // toss. That one rule is what stops grain turning into fake modules.
  //
  // `blur` is 0 or 1 passes of smoothing first, and the scan loop alternates
  // the two because neither wins everywhere. On a grainy frame (a dim room,
  // high ISO) the blur is what lets the code through at all. On a clean but
  // faint grey code it only merges the 4px modules of a code at the back of
  // the hall. Measured on bench/qr, one pass reads the most on its own, and the
  // two together read about a fifth more than either.
  //
  // `out` may be `data` itself: the frame is copied into the grey buffer
  // before anything is written.
  function binarize(data, w, h, blur, out) {
    smooth(data, w, h, blur);
    var sigma = noiseSigma(w, h);
    var W = w + 1;
    if (!sum || sum.length !== W * (h + 1)) {
      sum = new Float64Array(W * (h + 1));
      sq = new Float64Array(W * (h + 1));
    }
    for (var y = 0; y < h; y++) {
      var rs = 0, rq = 0;
      for (var x = 0; x < w; x++) {
        var v = grey[y * w + x];
        rs += v; rq += v * v;
        sum[(y + 1) * W + x + 1] = sum[y * W + x + 1] + rs;
        sq[(y + 1) * W + x + 1] = sq[y * W + x + 1] + rq;
      }
    }
    // 55px on a 640 crop: about five modules of a code at arm's length, so a
    // finder pattern's dark centre always has its light ring in view, and
    // still narrow enough to follow a glare falloff across the symbol.
    var rad = Math.max(6, Math.round(Math.min(w, h) / 24));
    var floor = 2.5 * sigma + 2, floor2 = floor * floor;
    out = out || new Uint8ClampedArray(w * h * 4);
    for (var y3 = 0; y3 < h; y3++) {
      var y0 = Math.max(0, y3 - rad), y1 = Math.min(h, y3 + rad + 1);
      for (var x3 = 0; x3 < w; x3++) {
        var x0 = Math.max(0, x3 - rad), x1 = Math.min(w, x3 + rad + 1);
        var cnt = (y1 - y0) * (x1 - x0);
        var s = sum[y1 * W + x1] - sum[y0 * W + x1] - sum[y1 * W + x0] + sum[y0 * W + x0];
        var q = sq[y1 * W + x1] - sq[y0 * W + x1] - sq[y1 * W + x0] + sq[y0 * W + x0];
        var mean = s / cnt;
        // Variance against the squared floor: no sqrt per pixel.
        var black = q / cnt - mean * mean > floor2 && grey[y3 * w + x3] < mean;
        var o = (y3 * w + x3) * 4, c = black ? 0 : 255;
        out[o] = out[o + 1] = out[o + 2] = c;
        out[o + 3] = 255;
      }
    }
    return out;
  }

  var api = { binarize: binarize };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.QREnhance = api;
})(this);
