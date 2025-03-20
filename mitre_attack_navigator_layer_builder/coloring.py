from dataclasses import dataclass
import re
from typing import Dict, List
import logging
import nearest_colours

logger = logging.getLogger(__name__)


HEX_COLOR_REGEX = re.compile(r'^#?([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$')


def is_hex_color(value: str) -> bool:
    return bool(HEX_COLOR_REGEX.match(value))


def get_hex_color_value(color: str) -> str:
    if is_hex_color(color):
        return color
    else:    
        for label, f in [
            ('W3C', nearest_colours.nearest_w3c),
            ('X11', nearest_colours.nearest_x11),
        ]:
            try:
                for c in f(color):
                    h = c.get_hex_l()
                    logger.debug(f"Resolved color '{color}' to '{h}'")
                    return h
            except ValueError:
                continue
    raise ValueError(f"Unrecognized color: {color}")


def get_color_gradient(a: str, b: str, n: int) -> List[str]:
    a = get_hex_color_value(a)
    b = get_hex_color_value(b)

    start_rgb = tuple(int(a[i : i + 2], 16) for i in (1, 3, 5))
    end_rgb = tuple(int(b[i : i + 2], 16) for i in (1, 3, 5))
    
    r_step = (end_rgb[0] - start_rgb[0]) / n
    g_step = (end_rgb[1] - start_rgb[1]) / n
    b_step = (end_rgb[2] - start_rgb[2]) / n
    gradient = []
    for step in range(n):
        r = int(start_rgb[0] + r_step * step)
        g = int(start_rgb[1] + g_step * step)
        b = int(start_rgb[2] + b_step * step)
        color = "#{:02x}{:02x}{:02x}".format(r, g, b)
        gradient.append(color)
    return gradient


@dataclass()
class ColorScheme:
    def get_colors(self) -> List[str]:
        raise NotImplementedError()


@dataclass()
class SingleColorScheme(ColorScheme):
    color: str = 'cornflowerblue'

    def get_colors(self) -> List[str]:
        return [self.color]


@dataclass()
class LabeledColorScheme(ColorScheme):
    colors_to_labels: Dict[str, str]

    def get_colors(self) -> List[str]:
        return list(self.colors_to_labels.keys())
    
    def __dict__(self) -> Dict[str, str]:
        return self.colors_to_labels
    

@dataclass()
class DiffColorScheme:
    left_color: str = 'lightcoral'
    right_color: str = 'lightgreen'
    unchanged_color: str = 'gray'


# TODO: pick default colors
@dataclass()
class IntersectionColorScheme:
    left_color: str = 'lightblue'
    right_color: str = 'lightcoral'
    intersection_color: str = 'mistyrose'


@dataclass()
class GradientColorScheme(ColorScheme):
    min_color: str
    max_color: str

    def get_colors(self, total_samples: int) -> List[str]:
        return get_color_gradient(self.min_color, self.max_color, total_samples)
    
    def get_color_map(self, total_samples: int) -> Dict[int, str]:
        return {i: color for i, color in enumerate(self.get_colors(total_samples), start=1)}


# TODO: test
def get_symmetric_diff_color_scheme(removed_color: str = 'lightcoral', added_color: str = 'lightgreen', unchanged_color: str = 'gray') -> DiffColorScheme:
    return DiffColorScheme(left_color=removed_color, right_color=added_color, unchanged_color=unchanged_color)


# TODO: test
def get_diff_color_scheme(left_color: str = 'lightcoral', right_color: str = 'lightgreen', unchanged_color: str = 'gray') -> DiffColorScheme:
    return LabeledColorScheme({
        left_color: 'left',
        right_color: 'right',
        unchanged_color: 'unchanged',
    })


def get_intersection_color_scheme(left_color: str = 'lightcoral', right_color: str = 'lightgreen', intersection_color: str = 'lightblue') -> IntersectionColorScheme:
    return IntersectionColorScheme(left_color=left_color, right_color=right_color, intersection_color=intersection_color)
