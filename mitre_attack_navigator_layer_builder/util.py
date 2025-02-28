import datetime
import functools
import pandas as pd
import gzip
import json
import os
import re
import string
from typing import Any, Dict, List
from uuid import UUID
import nearest_colours
from stix2.base import _STIXBase
import dataclasses
from json.encoder import JSONEncoder as _JSONEncoder


class JSONEncoder(_JSONEncoder):
    """
    A custom JSON encoder which includes support for serializing dataclasses, STIX 2 objects, UUIDs, dates, and datetime objects.
    """
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        elif isinstance(o, UUID):
            return str(o)
        elif isinstance(o, _STIXBase):
            return json.loads(o.serialize(pretty=True))
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        else:
            return super().default(o)


HEX_COLOR_REGEX = re.compile(r'^#?([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$')


def is_hex_color(value: str) -> bool:
    """
    Check if a string is a valid hex color (e.g. #ff0000).
    """    
    return bool(HEX_COLOR_REGEX.match(value))

    
def get_hex_color_value(color: str) -> str:
    """
    Get the hex value of a color.
    
    If the color is already a hex value, it is returned as is.
    
    Otherwise, the nearest named color is returned (e.g. cornflowerblue -> #6495ed).
    """
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


def is_hex_string(value: str) -> bool:
    """
    Determine if the provided value is a valid hex string (e.g. #c0ffee, 0xdeadbeef).
    """
    for prefix in ['#', '0x']:
        if value.startswith(prefix):
            value = value[len(prefix):]
            break    
    try:
        assert all(c in string.hexdigits for c in value)
    except AssertionError:
        return False
    else:
        return True


def get_color_gradient(a: str, b: str, n: int) -> List[str]:
    """
    Generate a gradient of colors between `a` and `b` with `n` steps.
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


def prune_dict(d) -> dict:
    """
    Recursively remove all null values from the provided dictionary.
    """
    if isinstance(d, dict):
        return {k: prune_dict(v) for k, v in d.items() if v is not None}
    elif is_iterable(d) and not isinstance(d, (str, bytes)):
        return [prune_dict(v) for v in d]
    else:
        return d
    

def is_iterable(o: Any) -> bool:
    try:
        iter(o)
    except TypeError:
        return False
    else:
        return True


def read_json_file(path: str) -> Any:
    """
    Read the JSON file.
    
    If the file is GZIP compressed, it will be decompressed on the fly.
    
    :param path: The path to the JSON file.
    :return: The JSON data.
    """
    path = get_real_path(path)
    if path.endswith('.gz'):
        f = functools.partial(gzip.open, mode='rt')
    else:
        f = functools.partial(open, mode='r')

    with f(path) as fp:
        return json.load(fp)


def get_real_path(path: str) -> str:
    """
    Get the real path of the provided path by:
    
    - Expanding the user directory (e.g. ~/ -> /home/user).
    - Expanding environment variables (e.g. $HOME -> /home/user).
    - Expanding the user directory (e.g. ~/ -> /home/user).
    - Resolving symbolic links.
    """
    for f in [
        os.path.expanduser,
        os.path.expandvars,
        os.path.expanduser,
        os.path.realpath,
    ]:
        path = f(path)
    return path


# TODO: here
# TODO: add support for iterables of dicts
# TODO: add support for polars dataframes
# TODO: apply a pivot policy (i.e. to select rows used for columns, rows, and the cell values)
def create_excel_workbook(sheets: Dict[str, pd.DataFrame], path: str) -> None:
    with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
        for sheet_name, df in sheets.items():
            df.to_excel(writer, sheet_name=sheet_name)
