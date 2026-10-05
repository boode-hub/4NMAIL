// Background lightning: every so often a thin bolt flickers across the sky in
// the accent colour, with a soft glow where it lands — a storm in the
// distance, never in the way.
//
// Pure decoration: behind every panel, ignores the mouse, pauses while the tab
// is hidden, follows the theme colour picker (it draws with var(--accent)),
// and stays off for anyone whose system asks for reduced motion.

const SVG = "http://www.w3.org/2000/svg";
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

const layer = document.createElement("div");
layer.className = "storm";
layer.setAttribute("aria-hidden", "true");
const glow = document.createElement("div");
glow.className = "storm-glow";
const bolts = document.createElementNS(SVG, "svg");
bolts.setAttribute("class", "storm-bolts");
layer.append(glow, bolts);
document.body.prepend(layer);

const between = (a, b) => a + Math.random() * (b - a);

/** A jagged line downwards from (x, y): short steps, each nudged sideways, kept within [min, max]. */
function jagged(x, y, endY, spread, drift = 0, [min, max] = [-Infinity, Infinity]) {
  const points = [[x, y]];
  while (y < endY) {
    y += between(12, 34);
    x = Math.min(max, Math.max(min, x + (Math.random() - 0.5) * spread + drift));
    points.push([x, y]);
  }
  return points;
}

function addPath(points, className) {
  const path = document.createElementNS(SVG, "path");
  path.setAttribute("d", `M${points.map(([x, y]) => `${x.toFixed(1)} ${y.toFixed(1)}`).join("L")}`);
  path.setAttribute("class", className);
  path.setAttribute("pathLength", "1"); // lets CSS draw it in, whatever its length
  bolts.append(path);
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

function strike() {
  const width = innerWidth;
  const height = innerHeight;
  const band = strikeBand(width);
  const x = between(band[0], band[1]);
  bolts.setAttribute("viewBox", `0 0 ${width} ${height}`);
  bolts.replaceChildren();

  const trunk = jagged(x, -10, height * between(0.4, 0.8), 46, 0, band);
  addPath(trunk, "bolt-trunk");
  // A few forks peel off the main channel, thinner and fading sooner.
  const forks = 1 + Math.floor(Math.random() * 3);
  for (let i = 0; i < forks; i++) {
    const [fx, fy] = trunk[1 + Math.floor(Math.random() * (trunk.length - 2))];
    addPath(jagged(fx, fy, fy + between(60, 200), 30, (Math.random() < 0.5 ? -1 : 1) * between(6, 14)), "bolt-fork");
  }

  glow.style.setProperty("--strike-x", `${((x / width) * 100).toFixed(1)}%`);
  // Restart the animation even if the last one has not finished.
  layer.classList.remove("striking");
  void layer.offsetWidth;
  layer.classList.add("striking");
}

function schedule(delay) {
  setTimeout(() => {
    if (!document.hidden && !reducedMotion.matches) {
      strike();
      // Now and then a second flash follows the first, as real lightning does.
      if (Math.random() < 0.25) setTimeout(strike, between(500, 900));
    }
    schedule(between(9000, 24000));
  }, delay);
}

schedule(between(3000, 7000));
