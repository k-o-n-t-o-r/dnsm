#!/usr/bin/env bash
set -euo pipefail

# Combine two screenshots side-by-side on a dark background with margins,
# a vertically centered (not full-height) separator, and a subtle outer border.
# Defaults match the current project styling.

# Usage:
#   scripts/combine_screenshots.sh [left_inbox.png] [right_browser.png] [output.png]
#
# Env overrides:
#   BGCOLOR       (default: #0a0e12)
#   SEP_COLOR_HEX (default: #33f1a0)
#   SEP_ALPHA     (default: 0.3)
#   SEP_WIDTH     (default: 3)
#   BORDER        (default: 40)
#   OUT_BORDER    (default: 3)
#   LEFT_GRAVITY  (default: north)   # top-align left image
#   RIGHT_GRAVITY (default: center)  # vertically center right image

IN="${1:-static/screenshots/inbox.png}"
BT="${2:-static/screenshots/browser_test.png}"
OUT="${3:-static/screenshots/combined_inbox_browser.png}"

BGCOLOR="${BGCOLOR:-#0a0e12}"
SEP_COLOR_HEX="${SEP_COLOR_HEX:-#33f1a0}"
SEP_ALPHA="${SEP_ALPHA:-0.3}"
SEP_WIDTH="${SEP_WIDTH:-3}"
BORDER="${BORDER:-40}"
OUT_BORDER="${OUT_BORDER:-3}"
LEFT_GRAVITY="${LEFT_GRAVITY:-north}"
RIGHT_GRAVITY="${RIGHT_GRAVITY:-center}"

if ! command -v magick >/dev/null 2>&1; then
  echo "Error: ImageMagick 'magick' CLI not found. Please install ImageMagick 7+." >&2
  exit 1
fi

if [ ! -f "$IN" ] || [ ! -f "$BT" ]; then
  echo "Error: Input files not found.\n  Left: $IN\n  Right: $BT" >&2
  exit 1
fi

# Convert hex color (e.g., #33f1a0) to r,g,b
hex=${SEP_COLOR_HEX#\#}
if [ ${#hex} -ne 6 ]; then
  echo "Error: SEP_COLOR_HEX must be 6-digit hex (e.g., #33f1a0). Got: $SEP_COLOR_HEX" >&2
  exit 1
fi
R=$((16#${hex:0:2}))
G=$((16#${hex:2:2}))
B=$((16#${hex:4:2}))
SEP_COLOR_RGBA="rgba(${R},${G},${B},${SEP_ALPHA})"

# Read input dimensions
W1=$(magick identify -format "%w" "$IN")
H1=$(magick identify -format "%h" "$IN")
W2=$(magick identify -format "%w" "$BT")
H2=$(magick identify -format "%h" "$BT")

# Dimensions after adding margins (BORDER on all sides of each tile)
W1B=$(( W1 + 2*BORDER ))
H1B=$(( H1 + 2*BORDER ))
W2B=$(( W2 + 2*BORDER ))
H2B=$(( H2 + 2*BORDER ))
HMAX=$(( H1B>H2B ? H1B : H2B ))

# Separator: centered vertically with top/bottom gaps equal to BORDER
SEP_H=$(( HMAX - 2*BORDER ))
if [ "$SEP_H" -lt 1 ]; then SEP_H=1; fi

TMP=$(mktemp --suffix=.png)
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

# Compose: left (top-aligned), separator (short), right (centered)
magick \
  \( "$IN" -bordercolor "$BGCOLOR" -border ${BORDER}x${BORDER} -background "$BGCOLOR" -gravity "$LEFT_GRAVITY" -extent ${W1B}x${HMAX} \) \
  \( -size ${SEP_WIDTH}x${HMAX} canvas:"$BGCOLOR" \( -size ${SEP_WIDTH}x${SEP_H} canvas:"$SEP_COLOR_RGBA" \) -gravity center -compose over -composite \) \
  \( "$BT" -bordercolor "$BGCOLOR" -border ${BORDER}x${BORDER} -background "$BGCOLOR" -gravity "$RIGHT_GRAVITY" -extent ${W2B}x${HMAX} \) \
  +append -background "$BGCOLOR" -alpha remove -alpha off "$TMP"

# Add a semi-transparent outer border similar to the separator
W=$(magick identify -format "%w" "$TMP")
H=$(magick identify -format "%h" "$TMP")

magick \
  "$TMP" \
  \( -size ${W}x${H} canvas:none \
     -stroke "$SEP_COLOR_HEX" -strokewidth ${OUT_BORDER} -fill none \
     -draw "rectangle 1,1 $((W-2)),$((H-2))" \
     -alpha set -channel A -evaluate set "$(awk -v a="$SEP_ALPHA" 'BEGIN{printf "%d%%", a*100}')" +channel \
   \) \
  -compose over -composite -background "$BGCOLOR" -alpha remove -alpha off "$OUT"

echo "Wrote $OUT ($(magick identify -format '%wx%h' "$OUT"))"

