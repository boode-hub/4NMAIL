// Background lightning: every so often a bolt tears down the sky in the accent
// colour — a white-hot core in a coloured glow, forks that fork again, and the
// flicker of real lightning: a leader racing down, then a few return strokes
// that light the whole sky, fading into an afterglow.
//
// Pure decoration: behind every panel, ignores the mouse, pauses while the tab
// is hidden, follows the theme colour picker (it draws with var(--accent)),
// and stays off for anyone whose system asks for reduced motion.

const SVG = "http://www.w3.org/2000/svg";
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

const layer = document.createElement("div");
layer.className = "storm";
layer.setAttribute("aria-hidden", "true");
const sky = document.createElement("div");
sky.className = "storm-sky";
const glow = document.createElement("div");
glow.className = "storm-glow";
const bolts = document.createElementNS(SVG, "svg");
bolts.setAttribute("class", "storm-bolts");
const halo = document.createElementNS(SVG, "g");
halo.setAttribute("class", "bolt-halo");
const body = document.createElementNS(SVG, "g");
body.setAttribute("class", "bolt-body");
const core = document.createElementNS(SVG, "g");
core.setAttribute("class", "bolt-core");
bolts.append(halo, body, core);
layer.append(sky, glow, bolts);
document.body.prepend(layer);

const between = (a, b) => a + Math.random() * (b - a);

/**
 * A lightning channel from one point to another by midpoint displacement:
 * each pass splits every segment and pushes its middle sideways by up to half
 * the previous amount — the jagged-at-every-scale look of real lightning.
 */
function channel(x1, y1, x2, y2, roughness, passes = 6) {
  let points = [[x1, y1], [x2, y2]];
  let offset = Math.hypot(x2 - x1, y2 - y1) * roughness;
  for (let pass = 0; pass < passes; pass++) {
    const next = [points[0]];
    for (let i = 0; i < points.length - 1; i++) {
      const [ax, ay] = points[i];
      const [bx, by] = points[i + 1];
      const len = Math.hypot(bx - ax, by - ay) || 1;
      const d = (Math.random() - 0.5) * 2 * offset;
      next.push([(ax + bx) / 2 - ((by - ay) / len) * d, (ay + by) / 2 + ((bx - ax) / len) * d], points[i + 1]);
    }
    points = next;
    offset /= 2;
  }
  return points;
}

/**
 * Draw one channel, thinning towards its end, in three layers: a wide soft
 * halo, the coloured body and a near-white core. Returns the paths so the
 * leader can be animated racing down them.
 */
function draw(points, width, delay) {
  const paths = [];
  const chunks = 4;
  const size = Math.ceil((points.length - 1) / chunks);
  for (let k = 0; k < chunks; k++) {
    const part = points.slice(k * size, (k + 1) * size + 1);
    if (part.length < 2) break;
    const d = `M${part.map(([x, y]) => `${x.toFixed(1)} ${y.toFixed(1)}`).join("L")}`;
    const w = width * (1 - k * 0.2);
    for (const [group, scale] of [[halo, 7], [body, 2.2], [core, 0.9]]) {
      const path = document.createElementNS(SVG, "path");
      path.setAttribute("d", d);
      path.setAttribute("stroke-width", (w * scale).toFixed(2));
      path.setAttribute("pathLength", "1");
      group.append(path);
      paths.push({ path, delay: delay + k * 18 });
    }
  }
  return paths;
}

/** Forks leave the channel at an angle, shorter and thinner; some fork again. */
function forks(points, width, generation, delayBase) {
  const out = [];
  if (generation > 2) return out;
  const count = generation === 1 ? 2 + Math.floor(Math.random() * 3) : Math.random() < 0.5 ? 1 : 0;
  const [sx, sy] = points[0];
  const [ex, ey] = points[points.length - 1];
  const length = Math.hypot(ex - sx, ey - sy);
  const heading = Math.atan2(ey - sy, ex - sx);
  for (let i = 0; i < count; i++) {
    const at = Math.floor(between(0.12, 0.7) * points.length);
    const [fx, fy] = points[at];
    const angle = heading + (Math.random() < 0.5 ? -1 : 1) * between(0.35, 0.9);
    const forkLength = length * between(0.18, 0.4);
    const fork = channel(fx, fy, fx + Math.cos(angle) * forkLength, fy + Math.sin(angle) * forkLength, 0.22, 5);
    const delay = delayBase + (at / points.length) * 90;
    out.push(...draw(fork, width * 0.5, delay), ...forks(fork, width * 0.5, generation + 1, delay));
  }
  return out;
}

/**
 * Where to strike: in the empty margin beside the content, on a random side,
 * so the bolt is seen rather than hidden behind a panel. Returns the band the
 * main channel stays inside. Phones have no margin worth the name: anywhere.
 */
function strikeBand(width) {
  const content = document.querySelector(".app-container > *")?.getBoundingClientRect();
  const margin = content ? content.left : 0;
  if (margin < 24) return [width * 0.1, width * 0.9];
  const inset = Math.min(40, margin / 4);
  const band = [inset, margin - inset];
  return Math.random() < 0.5 ? band : [width - band[1], width - band[0]];
}

/**
 * The flicker of a real strike: two to four return strokes along the same
 * channel, each a little dimmer, separated by near-darkness, then an afterglow.
 * As keyframe offsets (0–1) over the strike's duration.
 */
function flicker() {
  const frames = [{ opacity: 0, offset: 0 }];
  let t = 0.07; // the leader reaching the ground
  let intensity = 1;
  const strokes = 2 + Math.floor(Math.random() * 3);
  for (let i = 0; i < strokes; i++) {
    frames.push({ opacity: intensity, offset: t });
    t += between(0.025, 0.05);
    frames.push({ opacity: intensity * between(0.05, 0.3), offset: t });
    t += between(0.03, 0.09);
    intensity *= between(0.72, 0.95);
  }
  frames.push({ opacity: intensity * 0.7, offset: Math.min(t, 0.75) });
  frames.push({ opacity: 0, offset: 1 });
  return frames;
}

let strikeId = 0;

function strike() {
  const id = ++strikeId;
  const width = innerWidth;
  const height = innerHeight;
  const band = strikeBand(width);
  const x = between(band[0], band[1]);
  const endY = height * between(0.55, 1.05);
  bolts.setAttribute("viewBox", `0 0 ${width} ${height}`);
  for (const group of [halo, body, core]) group.replaceChildren();

  // The main channel, kept inside the margin so it is seen.
  const main = channel(x, -20, x + between(-0.15, 0.15) * (band[1] - band[0]), endY, 0.12).map(([px, py]) => [
    Math.min(band[1] + 12, Math.max(band[0] - 12, px)),
    py,
  ]);
  const width0 = between(1.3, 1.9);
  const paths = [...draw(main, width0, 0), ...forks(main, width0, 1, 0)];

  // The stepped leader: every channel races down from where it starts.
  for (const { path, delay } of paths) {
    path.animate([{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 70, delay, easing: "ease-in", fill: "backwards" });
  }

  const duration = between(1100, 1600);
  const frames = flicker();
  glow.style.setProperty("--strike-x", `${((x / width) * 100).toFixed(1)}%`);
  const timing = { duration, easing: "linear" };
  bolts.animate(frames, timing);
  glow.animate(frames, timing);
  // The sky lights with the strokes but not the afterglow.
  sky.animate(frames.map((f) => ({ ...f, opacity: f.offset > 0.75 ? 0 : f.opacity })), timing).finished.then(
    () => {
      // Unless a newer strike has already drawn its own bolt.
      if (id === strikeId) for (const group of [halo, body, core]) group.replaceChildren();
    },
    () => {},
  );
}

function schedule(delay) {
  setTimeout(() => {
    if (!document.hidden && !reducedMotion.matches) {
      strike();
      // A third of the time the storm strikes again moments later.
      if (Math.random() < 0.33) setTimeout(strike, between(1300, 2200));
    }
    schedule(between(8000, 20000));
  }, delay);
}

schedule(between(2500, 6000));
