import dataclasses
import datetime
import functools
import gzip
import json
import re
import string
import os
from typing import Any, List
import uuid
from stix2.base import _STIXBase
import nearest_colours


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif isinstance(o, uuid.UUID):
            return str(o)
        elif isinstance(o, _STIXBase):
            return json.loads(o.serialize(pretty=True))
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        else:
            return super().default(o)
        
    
def prune_dict(o: dict) -> dict:
    if isinstance(o, dict):
        return {k: prune_dict(v) for k, v in o.items() if v is not None}
    elif isinstance(o, list):
        return [prune_dict(v) for v in o]
    else:
        return o


def read_json_file(path: str) -> Any:
    path = get_real_path(path)
    if path.endswith('.gz'):
        f = functools.partial(gzip.open, mode='rt')
    else:
        f = functools.partial(open, mode='r')

    with f(path) as fp:
        return json.load(fp)


def get_real_path(path: str) -> str:
    for f in [
        os.path.expanduser,
        os.path.expandvars,
        os.path.realpath,
    ]:
        path = f(path)
    return path


def get_color_gradient(a: str, b: str, n: int) -> List[str]:
    """
    Generate a color gradient between two hex colors (e.g. ).
    """
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


def is_hex_string(value: str) -> bool:
    try:
        parse_hex_string(value)
    except ValueError:
        return False
    return True


HEX_COLOR_REGEX = re.compile(r'^#?([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$')


def is_hex_color(value: str) -> bool:    
    return bool(HEX_COLOR_REGEX.match(value))


def is_web_color(value: str) -> bool:
    return is_hex_color(value)


def parse_hex_string(value: str) -> str:
    try:
        for prefix in ['#']:
            if value.startswith(prefix):
                value = value[len(prefix):]
                break
        assert all(c in string.hexdigits for c in value)
    except AssertionError as e:
        raise ValueError(f"Invalid hex string: {value}") from e
    return value


def get_hex_color_name(color: str) -> str:
    for c in nearest_colours.nearest_w3c(color):
        return c.get_web()

    
def get_hex_color_value(color: str) -> str:
    if is_hex_color(color):
        return color
    else:    
        for f in [
            nearest_colours.nearest_w3c,
            nearest_colours.nearest_x11,
        ]:
            try:
                for c in f(color):
                    return c.get_hex_l()
            except ValueError:
                continue
    raise ValueError(f"Unrecognized color: {color}")
