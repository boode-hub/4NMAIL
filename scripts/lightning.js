// Background lightning: now and then a bolt drops from the top of the page — a
// white core with the accent colour glowing round it and lighting the sky
// above, flickering out in about two thirds of a second. The style of
// qayssarayra.com's sky, drawn in this app's own colours.
//
// Pure decoration: a canvas behind every panel that ignores the mouse, draws
// only while a strike lasts, pauses while the tab is hidden, follows the theme
// colour picker (it reads --accent at each strike), and stays off for anyone
// whose system asks for reduced motion.

const canvas = document.createElement("canvas");
canvas.className = "lightning";
canvas.setAttribute("aria-hidden", "true");
document.body.prepend(canvas);
const g = canvas.getContext("2d");

const rand = (lo, hi) => lo + Math.random() * (hi - lo);

/** Each segment's midpoint pushed sideways (across the segment) by up to `push` pixels: one pass of jaggedness. */
function jag(points, push) {
  const out = [points[0]];
  for (let i = 1; i < points.length; i++) {
    const a = points[i - 1];
    const b = points[i];
    const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    const off = rand(-push, push);
    out.push({ x: (a.x + b.x) / 2 - ((b.y - a.y) / len) * off, y: (a.y + b.y) / 2 + ((b.x - a.x) / len) * off }, b);
  }
  return out;
}

/**
 * Where a strike may start: in the empty margin beside the content, where it
 * can be seen; anywhere across the middle when the margins are too narrow.
 */
function strikeBand(width) {
  const content = document.querySelector(".app-container > *")?.getBoundingClientRect();
  const margin = content ? content.left : 0;
  if (margin < 24) return [width * 0.12, width * 0.88];
  const inset = Math.min(40, margin / 4);
  const band = [inset, margin - inset];
  return Math.random() < 0.5 ? band : [width - band[1], width - band[0]];
}

/**
 * A strike: from above the top edge to a third or two-thirds down, in six to
 * nine steps that drift with a slowly changing lean, then jagged twice; most
 * strikes with one to three short branches off to one side.
 */
function bolt(w, h) {
  const steps = Math.round(rand(6, 9));
  const end = rand(h * 0.34, h * 0.72);
  let x = rand(...strikeBand(w));
  let lean = rand(-0.45, 0.45);
  let points = [{ x, y: -12 }];
  for (let i = 1; i <= steps; i++) {
    lean += rand(-0.2, 0.2);
    x += rand(-24, 24) + lean * 16;
    points.push({ x, y: -12 + (end + 12) * (i / steps) });
  }
  points = jag(jag(points, 9), 4);
  const branches = [];
  const count = Math.random() < 0.72 ? Math.round(rand(1, 3)) : 0;
  for (let b = 0; b < count; b++) {
    const from = points[Math.round(rand(2, points.length - 2))];
    const side = Math.random() < 0.5 ? -1 : 1;
    const branch = [from];
    let { x: bx, y: by } = from;
    for (let i = Math.round(rand(2, 4)); i > 0; i--) {
      bx += side * rand(10, 42);
      by += rand(16, 46);
      branch.push({ x: bx, y: by });
    }
    branches.push(jag(branch, 5));
  }
  return { points, branches };
}

/** How bright the strike is, `t` ms in: a flash, nearly out, a second flash, out, a third weaker one, then a fade. Zero when done. */
function brightness(t) {
  if (t < 55) return 1;
  if (t < 105) return 0.12;
  if (t < 165) return 0.86;
  if (t < 215) return 0.08;
  if (t < 275) return 0.46;
  if (t < 620) return 0.46 * (1 - (t - 275) / 345);
  return 0;
}

/** The theme colour as "r, g, b", read when a strike starts, so a changed accent is used at once. */
function accentRgb() {
  const hex = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
  const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex);
  return m ? `${parseInt(m[1], 16)}, ${parseInt(m[2], 16)}, ${parseInt(m[3], 16)}` : "159, 239, 0";
}

function line(points) {
  g.beginPath();
  g.moveTo(points[0].x, points[0].y);
  for (const p of points.slice(1)) g.lineTo(p.x, p.y);
  g.stroke();
}

function schedule(first = false) {
  setTimeout(strike, first ? rand(2600, 7000) : rand(9000, 27000));
}

function strike() {
  if (document.hidden || matchMedia("(prefers-reduced-motion: reduce)").matches) return schedule();
  // Sized at each strike, so a resized window is drawn at its own size and resolution.
  const ratio = Math.min(devicePixelRatio || 1, 2);
  const w = innerWidth;
  const h = innerHeight;
  canvas.width = Math.round(w * ratio);
  canvas.height = Math.round(h * ratio);
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  const b = bolt(w, h);
  const glow = accentRgb();
  const start = performance.now();
  const draw = (now) => {
    const v = brightness(now - start);
    g.clearRect(0, 0, w, h);
    if (v <= 0) return schedule();
    // The sky lit from where it leaves the cloud.
    const sky = g.createRadialGradient(b.points[0].x, 0, 0, b.points[0].x, 0, Math.max(w, h) * 0.9);
    sky.addColorStop(0, `rgba(${glow}, ${0.1 * v})`);
    sky.addColorStop(0.4, `rgba(${glow}, ${0.032 * v})`);
    sky.addColorStop(1, `rgba(${glow}, 0)`);
    g.fillStyle = sky;
    g.fillRect(0, 0, w, h);
    g.lineCap = "round";
    g.lineJoin = "round";
    g.strokeStyle = `rgba(${glow}, ${0.38 * v})`;
    g.lineWidth = 8;
    line(b.points);
    g.strokeStyle = `rgba(255, 255, 255, ${Math.min(1, 1.05 * v)})`;
    g.lineWidth = 1.8;
    line(b.points);
    g.strokeStyle = `rgba(255, 255, 255, ${0.5 * v})`;
    g.lineWidth = 1;
    for (const br of b.branches) line(br);
    requestAnimationFrame(draw);
  };
  requestAnimationFrame(draw);
}

if (g) schedule(true);
