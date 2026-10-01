"""Generate the CyberSentinel Desktop Windows icon (build/icon.ico).

Uses only the Python standard library (struct, zlib, pathlib). The .ico
embeds a 256x256 PNG, which is valid for Windows Vista and later.
"""
import pathlib
import struct
import zlib

SIZE = 256
BG = (8, 12, 18)
PANEL = (15, 22, 34)
ACCENT = (34, 211, 238)

FONT = {
    "C": ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
    "S": ["01111", "11000", "10000", "01110", "00001", "00011", "11110"],
}


def in_shield(x, y):
    cx = SIZE / 2.0
    top, mid, bottom, half = 28.0, 140.0, 225.0, 86.0
    if y < top or y > bottom:
        return False
    if y <= mid:
        width = half
    else:
        width = half * (1.0 - (y - mid) / (bottom - mid))
    return abs(x - cx) <= width


def draw_glyph(grid, char, ox, oy, scale):
    for row_index, row in enumerate(FONT[char]):
        for col_index, bit in enumerate(row):
            if bit != "1":
                continue
            for dy in range(scale):
                for dx in range(scale):
                    grid[oy + row_index * scale + dy][ox + col_index * scale + dx] = ACCENT


def build_grid():
    grid = [[BG for _ in range(SIZE)] for _ in range(SIZE)]
    for y in range(SIZE):
        for x in range(SIZE):
            if not in_shield(x, y):
                continue
            edge = not (
                in_shield(x + 1, y) and in_shield(x - 1, y)
                and in_shield(x, y + 1) and in_shield(x, y - 1)
            )
            grid[y][x] = ACCENT if edge else PANEL
    scale = 10
    width = 5 * scale
    gap = 4 * scale
    total = 2 * width + gap
    ox = (SIZE - total) // 2
    draw_glyph(grid, "C", ox, 92, scale)
    draw_glyph(grid, "S", ox + width + gap, 92, scale)
    return grid


def encode_png(grid):
    raw = bytearray()
    for row in grid:
        raw.append(0)
        for pixel in row:
            raw.extend(pixel)

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += chunk(b"IEND", b"")
    return png


def main():
    png = encode_png(build_grid())
    ico = struct.pack("<HHH", 0, 1, 1)
    ico += struct.pack("<BBBBHHII", 0, 0, 0, 0, 1, 32, len(png), 22)
    ico += png
    out = pathlib.Path(__file__).resolve().parents[1] / "build" / "icon.ico"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(ico)
    print("wrote", out, len(ico), "bytes")


if __name__ == "__main__":
    main()
