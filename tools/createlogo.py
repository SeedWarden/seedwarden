"""
SeedWarden logo generator (SVG → PNG)
"""

import subprocess
from pathlib import Path

OUTPUT_DIR = Path(Path().cwd(), "src", "seedwarden", "resources", "img")
OUTPUT_DIR.mkdir(exist_ok=True)


# ------------------------------------------------------------------
# Build the SVG string
# ------------------------------------------------------------------
def create_svg(padding: int = 10) -> str:

    # configuration values
    SIZE = 512  # base canvas size (SVG units)

    ORANGE = "#FF6A00"
    WHITE = "#f0f0f0"

    TOP = padding
    BOTTOM = SIZE - TOP
    LEFT = padding + 30
    RIGHT = SIZE - LEFT
    CENTER_X = SIZE // 2

    LINE1_Y = TOP + 140
    LINE2_Y = TOP + 250

    # Bezier curve values
    BEZ0_Y = TOP + (BOTTOM - TOP) * 2 // 3
    BEZ1_Y = BEZ0_Y + (BOTTOM - BEZ0_Y) // 2
    BEZ2_W = (CENTER_X - LEFT) // 2
    BEZ2_Y = BOTTOM - 50

    parts = []
    parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     width="{SIZE}" height="{SIZE}"
     viewBox="0 0 {SIZE} {SIZE}">

  <style>
    path.outline {{
      fill: none;
      stroke: {ORANGE};
      stroke-width: 10;
      stroke-linejoin: miter;
    }}

    text {{ 
      font-family: Courier new, sans-serif;
      font-size: 110px;
      font-weight: bold;
      dominant-baseline: middle;
    }}

    text.left {{
      text-anchor: end;
      fill: {ORANGE};
    }}

    text.right {{
      text-anchor: start;
      fill: {WHITE};
    }}
  </style>
''')

    # right half
    right_path = (
        f"V{BEZ0_Y} C{RIGHT} {BEZ1_Y} {RIGHT - BEZ2_W} {BEZ2_Y} {CENTER_X} {BOTTOM}"
    )
    parts.append(f'''  <path
        d="M{CENTER_X} {TOP} H{RIGHT}{right_path} Z"
        fill="{ORANGE}"/>
''')

    # left half
    left_path = f"C{LEFT + BEZ2_W} {BEZ2_Y} {LEFT} {BEZ1_Y} {LEFT} {BEZ0_Y} V{TOP}"
    parts.append(f'''  <path
        d="M{CENTER_X} {TOP} V{BOTTOM} {left_path} Z"
        fill="{WHITE}"/>
''')

    # outline
    parts.append(f"""  <path
        d="M{RIGHT} {TOP} {right_path} {left_path} Z"
        class="outline"/>
""")

    # text
    parts.append(f'''<text x="{CENTER_X - 1}" y="{LINE1_Y}" class="left">SE</text>''')
    parts.append(f'''<text x="{CENTER_X + 1}" y="{LINE1_Y}" class="right">ED</text>''')
    parts.append(f'''<text x="{CENTER_X - 1}" y="{LINE2_Y}" class="left">WAR</text>''')
    parts.append(f'''<text x="{CENTER_X + 1}" y="{LINE2_Y}" class="right">DEN</text>''')

    parts.append("</svg>")
    return "\n".join(parts)


# ------------------------------------------------------------------
# 3. Save SVG and convert to several PNG sizes
# ------------------------------------------------------------------
def main():
    svg_content = create_svg()
    # print(svg_content)
    svg_path = OUTPUT_DIR / "logo.svg"
    svg_path.write_text(svg_content, encoding="utf-8")
    print(f"SVG saved → {svg_path}")

    # Sizes you typically need for a logo
    sizes = [64, 128, 256, 512, 1024]

    for s in sizes:
        png_path = OUTPUT_DIR / f"logo_{s}.png"
        # ImageMagick convert (available in this environment)
        cmd = [
            "inkscape",
            str(svg_path),
            "-w",
            str(s),
            "--export-type=png",
            f"--export-filename={png_path}",
        ]
        subprocess.run(cmd, check=True)
        print(f"PNG  {s}×{s} → {png_path}")

    print("\nDone! Open logo_output/logo.svg in a browser or any SVG viewer.")
    print(
        "If you want to change the design, edit the parameters at the top and re-run."
    )


if __name__ == "__main__":
    main()
