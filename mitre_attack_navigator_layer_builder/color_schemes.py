from typing import List, Optional
from pydantic import BaseModel

import nearest_colours


class GradientColorScheme(BaseModel):
    start: str
    end: str


class DiffColorScheme(BaseModel):
    removed: str
    unchanged: str
    added: str


REDS = GradientColorScheme(start="#ffb48e", end="#9e0000")
GREENS = GradientColorScheme(start="#98fa7d", end="#1b9e0b")
BLUES = GradientColorScheme(start="#b3e7ff", end="#064a75")
PURPLES = GradientColorScheme(start="#ffb4ff", end="#9e009e")
ORANGES = GradientColorScheme(start="#ffb786", end="#ff5e30")

PASTEL_DIFF = DiffColorScheme(removed="#B0FFB3", unchanged="#FFFFB3", added="#FFB3B3")

DEFAULT_DIFF_COLOR_SCHEME = PASTEL_DIFF
DEFAULT_SINGLE_HUE_COLOR_SCHEME = BLUES


def generate_color_gradient(start_color: str, end_color: str, steps: int) -> List[str]:
    # Convert the start and end colors to RGB values
    start_rgb = tuple(int(start_color[i : i + 2], 16) for i in (1, 3, 5))
    end_rgb = tuple(int(end_color[i : i + 2], 16) for i in (1, 3, 5))

    # Calculate the step size for each RGB component
    r_step = (end_rgb[0] - start_rgb[0]) / steps
    g_step = (end_rgb[1] - start_rgb[1]) / steps
    b_step = (end_rgb[2] - start_rgb[2]) / steps

    # Generate the color gradient
    gradient = []
    for step in range(steps):
        # Calculate the RGB values for the current step
        r = int(start_rgb[0] + r_step * step)
        g = int(start_rgb[1] + g_step * step)
        b = int(start_rgb[2] + b_step * step)

        # Convert the RGB values to a hex-coded color
        color = "#{:02x}{:02x}{:02x}".format(r, g, b)
        gradient.append(color)

    return gradient


def get_hex_color_name(color: str) -> Optional[str]:
    """
    Convert a hex color code to a color name (e.g. #daa520 -> goldenrod)
    """
    nearest = nearest_colours.nearest_w3c(color)
    if nearest:
        for color in nearest:
            return color.get_web()
