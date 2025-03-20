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


def is_hex_string(value: str) -> bool:
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


def prune_dict(d) -> dict:
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
