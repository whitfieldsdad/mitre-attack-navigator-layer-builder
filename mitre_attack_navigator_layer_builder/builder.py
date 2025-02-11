import collections
import dataclasses
import json
import sys
from typing import Iterable, List, Optional
from dataclasses import dataclass
import fnmatch
import dacite
from stix2 import Filter, MemorySource
from stix2.datastore import DataSource
import requests
from mitre_attack_navigator_layer_builder.constants import DEFAULT_COLOR, HEATMAP, JSON_INDENT, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN, UNION
from mitre_attack_navigator_layer_builder.types import Layer, Technique
from mitre_attack_navigator_layer_builder import util


@dataclass(frozen=True)
class ColorScheme:
    pass


@dataclass(frozen=True)
class SingleColorScheme(ColorScheme):
    color: str = DEFAULT_COLOR
    
    
@dataclass(frozen=True)
class DiffColorScheme(ColorScheme):
    added_color: str = 'green'
    unchanged_color: str = 'yellow'
    removed_color: str = 'red'
    

GIT_DIFF_COLOR_SCHEME = DiffColorScheme(
    added_color='green',
    unchanged_color='yellow',
    removed_color='red',
)


@dataclass(frozen=True)
class GradientColorScheme(ColorScheme):
    min_color: str = 'green'
    max_color: str = 'red'
    min_value: int = 0
    max_value: int = 100


@dataclass(frozen=True)
class LayerConfig:
    color_scheme: SingleColorScheme = SingleColorScheme(color=DEFAULT_COLOR)
    disable_deselected_techniques: bool = False
    hide_disabled_techniques: bool = False


def get_stix2_data_source_by_mitre_attack_domain(domain: str) -> DataSource:
    url = STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN[domain]
    return get_stix2_data_source(url)


# TODO: optionally disable TLS certificate verification (i.e., to support networks where DPI is being performed).
def get_stix2_data_source(path: str) -> DataSource:
    if path.startswith(('http://', 'https://')):
        response = requests.get(path, verify=True)
        response.raise_for_status()
        
        data = response.json()
        return MemorySource(data)
    else:
        with open(path) as fp:
            data = json.load(fp)
            return MemorySource(data)


# TODO: optionally disable deselected techniques
def generate_layer(domain: str, selected_techniques: List[str], config: Optional[LayerConfig] = None) -> Layer:
    config = config or LayerConfig()

    src = get_stix2_data_source_by_mitre_attack_domain(domain)
    attack_patterns = src.query([Filter('type', '=', 'attack-pattern')])
    
    layer = Layer(
        domain=domain,
        hideDisabled=config.hide_disabled_techniques,
    )
    
    all_technique_ids = {_extract_external_id(technique) for technique in attack_patterns}
    selected_techniques = set(map(str.upper, selected_techniques))

    for technique in selected_techniques:
        technique = Technique(
            techniqueID=technique,
            color=config.color_scheme.color,
        )
        layer.techniques.append(technique)
    
    if config.disable_deselected_techniques:
        for technique in all_technique_ids - selected_techniques:
            technique = Technique(
                techniqueID=technique,
                enabled=False,
            )
            layer.techniques.append(technique)

    return layer


def generate_enterprise_layer(selected_techniques: Optional[List[str]] = None, layer_config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_ENTERPRISE, selected_techniques=selected_techniques, config=layer_config)


def generate_mobile_layer(selected_techniques: Optional[List[str]] = None, config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_MOBILE, selected_techniques=selected_techniques, config=config)


def generate_ics_layer(selected_techniques: Optional[List[str]] = None, config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_ICS, selected_techniques=selected_techniques, config=config)


def parse_layer(o: dict) -> Layer:
    return dacite.from_dict(Layer, o)


def serialize_layer_to_dict(layer: Layer) -> dict:
    data = dataclasses.asdict(layer)
    data = util.prune_dict(data)
    return data


def serialize_layer_to_json(layer: Layer, indent: int = JSON_INDENT) -> str:
    data = serialize_layer_to_dict(layer)
    return json.dumps(data, cls=util.JSONEncoder, indent=indent)


# TODO
def merge_layers(layers: Iterable[Layer], merge_strategy: str = UNION) -> Layer:
    layers = list(layers)
    domains = {layer.domain for layer in layers}
    assert len(domains) == 1, f'Cannot merge layers from different domains: {domains}'

    if merge_strategy == HEATMAP:
        layer = _merge_layers_as_heatmap(layers)        
    else:
        raise ValueError(f'Invalid merge strategy: {merge_strategy}')
    
    return layer


def _merge_layers_as_heatmap(layers: List[Layer]) -> Layer:
    scores = collections.defaultdict(int)
    
    for layer in layers:
        for technique in layer.techniques:
            scores[technique.techniqueID] += 1
    
    techniques = []
    for technique_id, score in scores.items():
        technique = Technique(
            techniqueID=technique_id,
            score=score,
        )
        techniques.append(technique)

    gradient = GradientColorScheme(
        max_value=max(scores.values()),
    )
    return Layer(
        gradient=gradient,
        techniques=techniques,
    )


def _extract_external_id(o: dict) -> Optional[str]:
    for ref in o.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
