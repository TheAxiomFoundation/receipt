"""The motivating example as a figure: one correction, two paths.

Generates paper/figures/two-paths.png from the vendored house fonts, so the
figure re-renders byte-stably anywhere the repo is cloned:

    uvx --with matplotlib python paper/figures_src/make_two_paths.py
"""

from pathlib import Path

import matplotlib
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

matplotlib.use("Agg")

PAPER_DIR = Path(__file__).resolve().parents[1]
FONTS = PAPER_DIR / "_extensions" / "axiom" / "fonts"
OUT = PAPER_DIR / "figures" / "two-paths.png"

GEIST = fm.FontProperties(fname=str(FONTS / "geist" / "Geist-Regular.ttf"))
GEIST_B = fm.FontProperties(fname=str(FONTS / "geist" / "Geist-Bold.ttf"))
MONO = fm.FontProperties(
    fname=str(FONTS / "jetbrains-mono" / "JetBrainsMono-Regular.ttf")
)

INK = "#1c1917"
SECONDARY = "#57534e"
MUTED = "#78716c"
RULE = "#d6d3d1"
AMBER = "#b45309"
PAPER = "#faf9f6"

fig, ax = plt.subplots(figsize=(8.6, 4.35))
fig.patch.set_facecolor(PAPER)
ax.set_facecolor(PAPER)
ax.set_xlim(0, 100)
ax.set_ylim(-2.2, 50)
ax.axis("off")


def box(x, y, w, h, lines, *, edge=RULE, mono=False, title=None, lw=1.1):
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.55,rounding_size=0.9",
            facecolor="white",
            edgecolor=edge,
            linewidth=lw,
        )
    )
    ty = y + h - 1.1
    if title:
        ax.text(x + w / 2, ty, title, ha="center", va="top", fontsize=8.3,
                fontproperties=GEIST_B, color=INK)
        ty -= 3.4
    for line in lines:
        ax.text(x + w / 2, ty, line, ha="center", va="top",
                fontsize=7.1 if mono else 7.6,
                fontproperties=MONO if mono else GEIST, color=SECONDARY)
        ty -= 3.1


def arrow(x1, y1, x2, y2, *, color=MUTED, style="-|>"):
    ax.add_patch(
        FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle=style, mutation_scale=9,
            color=color, linewidth=1.15, shrinkA=2, shrinkB=2,
        )
    )


# ── the pipeline, once ──────────────────────────────────────────────
box(2, 40, 14, 6.5, [], title="orchestrator")
box(22, 40, 14, 6.5, [], title="encoder")
box(42, 40, 17, 6.5, [], title="validation gates")
box(65, 38.6, 31, 9.4, ["signed · witnessed · attested", "journal: rate.yaml e218ac6d2f12…"],
    title="release 0002", mono=False)
arrow(16.7, 43.2, 21.3, 43.2)
arrow(36.7, 43.2, 41.3, 43.2)
arrow(59.8, 43.2, 64.3, 43.2)

ax.text(2, 33.9, "the published rate reads 0.15; it should read 0.17",
        fontsize=8.1, fontproperties=GEIST_B, color=INK)

# ── lane A: the hand edit ───────────────────────────────────────────
ax.text(2, 29.3, "hand edit", fontsize=8.0, fontproperties=GEIST_B, color=AMBER)
box(2, 20.5, 30, 7.2, ["rules/tax/rate.yaml → 0.17", "journal and chain untouched"],
    edge=AMBER, mono=True)

box(2, 10.4, 30, 7.4,
    ["pull-request gate: producer CI refuses", "the unmanifested edit — producer's domain"],
    edge=RULE)
box(2, 0.0, 30, 9.6,
    ["any clone: receipt verify", "FAIL binding — tree c0f597cf00ba…", "journal binds e218ac6d2f12…"],
    edge=AMBER, mono=True)
arrow(17, 19.7, 17, 18.7, color=MUTED)
arrow(17, 10.3, 17, 10.1, color=AMBER)

# ── lane B: fix the encoder, re-encode ──────────────────────────────
ax.text(41, 29.3, "fix the encoder, re-encode", fontsize=8.0,
        fontproperties=GEIST_B, color=INK)
box(41, 20.5, 26, 7.2, ["encoder fixed → gates re-run"], edge=RULE)
box(71, 19.4, 27, 9.4, ["journal: rate.yaml c0f597cf00ba…"],
    title="release 0003", mono=False)
arrow(67.8, 24.1, 70.3, 24.1)

box(41, 0.6, 57, 7.8,
    ["any clone: receipt verify — PASS: chain of 3 release(s),", "every file bound to a witnessed digest"],
    edge=RULE, mono=True)
arrow(84, 18.6, 84, 9.3, color=MUTED)

fig.tight_layout(pad=0.4)
OUT.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(OUT, dpi=200, facecolor=PAPER, metadata={"Software": None})
print(f"wrote {OUT}")
