import functools
import gzip
import json

from pydantic import BaseModel
from mitre_attack_navigator_layer_builder.types.layer import Layer


def read_layer(path: str) -> Layer:
    """
    Reads a MITRE ATT&CK Navigator layer from a file.
    """
    if path.endswith(".gz"):
        f = functools.partial(gzip.open, mode="rt")
    else:
        f = functools.partial(open, mode="r")

    with f(path) as file:
        layer = json.load(file)
    return from_dict(layer)


def save_layer(layer: Layer, path: str, indent: int = 4) -> None:
    """
    Saves a MITRE ATT&CK Navigator layer to a file.
    """
    with open(path, "w") as file:
        data = to_dict(layer)
        json.dump(data, file, indent=indent)


def from_dict(data: dict) -> Layer:
    """
    Converts a dictionary to a Layer.
    """
    return Layer(**data)


def to_dict(data: BaseModel) -> dict:
    """
    Converts a class inheriting from pydantic.BaseModel to a dictionary.
    """
    return data.model_dump(exclude_unset=True)


def to_json(data: BaseModel, indent: int = 4) -> str:
    """
    Converts a class inheriting from pydantic.BaseModel to a JSON string.
    """
    return json.dumps(to_dict(data), indent=indent)
