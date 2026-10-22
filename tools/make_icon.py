"""Generate SoftSweep application icons from the vector brand mark."""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "assets"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def _cubic_point(start, control_1, control_2, end, t):
    mt = 1.0 - t
    return (
        mt**3 * start[0] + 3 * mt**2 * t * control_1[0] + 3 * mt * t**2 * control_2[0] + t**3 * end[0],
        mt**3 * start[1] + 3 * mt**2 * t * control_1[1] + 3 * mt * t**2 * control_2[1] + t**3 * end[1],
    )


def render(size: int) -> Image.Image:
    scale = size / 64.0
    supersample = 4
    canvas_size = size * supersample
    scale *= supersample

    image = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    pixels = image.load()

    for y in range(canvas_size):
        for x in range(canvas_size):
            nx, ny = x / canvas_size, y / canvas_size
            ratio = min(1.0, max(0.0, (nx + ny) / 2.0))
            red = round(0x1D * (1 - ratio) + 0x0F * ratio)
            green = round(0x7A * (1 - ratio) + 0x56 * ratio)
            blue = round(0x63 * (1 - ratio) + 0x45 * ratio)
            pixels[x, y] = (red, green, blue, 255)

    mask = Image.new("L", (canvas_size, canvas_size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, canvas_size - 1, canvas_size - 1],
        radius=int(16 * scale),
        fill=255,
    )
    background = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    background.paste(image, (0, 0), mask)

    draw = ImageDraw.Draw(background)
    stroke = 4.8 * scale

    def scaled(x: float, y: float) -> tuple[float, float]:
        return x * scale, y * scale

    def thick_line(start, end):
        draw.line([scaled(*start), scaled(*end)], fill=(255, 255, 255, 255), width=max(1, int(stroke)))
        radius = stroke / 2
        for x, y in (start, end):
            px, py = scaled(x, y)
            draw.ellipse(
                [px - radius, py - radius, px + radius, py + radius],
                fill=(255, 255, 255, 255),
            )

    thick_line((18, 18.4), (44, 18.4))
    thick_line((18, 28.4), (36, 28.4))

    curve = [
        _cubic_point((15, 43), (26.6, 48.6), (39.4, 46.2), (47.8, 36.8), t / 260.0)
        for t in range(261)
    ]
    radius = stroke / 2
    for x, y in curve:
        px, py = scaled(x, y)
        draw.ellipse([px - radius, py - radius, px + radius, py + radius], fill=(255, 255, 255, 255))

    cx, cy = scaled(47.2, 18.4)
    dot = 3.2 * scale
    draw.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=(255, 255, 255, 255))

    return background.resize((size, size), Image.Resampling.LANCZOS)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    master = render(256)
    master.save(OUTPUT_DIR / "app.png")
    variants = [render(size) for size in SIZES]
    variants[0].save(
        OUTPUT_DIR / "app.ico",
        sizes=tuple((image.width, image.height) for image in variants),
        append_images=variants[1:],
    )
    print(OUTPUT_DIR / "app.ico")
    print(OUTPUT_DIR / "app.png")


if __name__ == "__main__":
    main()
