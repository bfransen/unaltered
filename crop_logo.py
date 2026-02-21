#!/usr/bin/env python3
"""Crop unaltered_logo.jpg to the bounding box of the word and padlock (remove excess white)."""

from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Installing Pillow...")
    import subprocess
    subprocess.check_call(["pip", "install", "pillow"])
    from PIL import Image


def get_content_bbox(img: Image.Image, threshold: int = 250):
    # Returns (left, upper, right, lower)
    """Return (left, upper, right, lower) bounding box of pixels darker than threshold."""
    if img.mode != "RGB":
        img = img.convert("RGB")
    width, height = img.size
    pixels = img.load()

    left = width
    right = 0
    top = height
    bottom = 0

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            # Consider pixel as "content" if any channel is below threshold (not pure white)
            if r < threshold or g < threshold or b < threshold:
                left = min(left, x)
                right = max(right, x)
                top = min(top, y)
                bottom = max(bottom, y)

    if left > right or top > bottom:
        return (0, 0, width, height)  # fallback: no content found
    return (left, top, right + 1, bottom + 1)


def main() -> None:
    path = Path(__file__).resolve().parent / "unaltered_logo.jpg"
    if not path.exists():
        print(f"Not found: {path}")
        return
    img = Image.open(path)
    bbox = get_content_bbox(img)
    cropped = img.crop(bbox)
    # Add a small padding so the crop isn't flush against the edges
    pad = 8
    w, h = cropped.size
    padded = Image.new(img.mode, (w + 2 * pad, h + 2 * pad), (255, 255, 255))
    padded.paste(cropped, (pad, pad))
    padded.save(path)
    print(f"Cropped and saved: {path}")


if __name__ == "__main__":
    main()
