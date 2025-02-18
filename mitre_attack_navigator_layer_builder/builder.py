import collections
import dataclasses
import json
import stix2.base
from stix2 import Filter as _STIX2Filter
from typing import Dict, Iterable, List, Optional, Union
from dataclasses import dataclass
import dacite
import requests
from stix2.datastore import DataSource
from stix2.datastore.memory import MemorySource
from mitre_attack_navigator_layer_builder import util
from mitre_attack_navigator_layer_builder.constants import DEFAULT_COLOR, HEATMAP, JSON_INDENT, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN, UNION
from mitre_attack_navigator_layer_builder.layers import Gradient, Layer, Technique

import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ColorScheme:
    """
    A color scheme to apply when generating layers.
    """
    def get_colors(self, *args, **kwargs) -> List[str]:
        """
        Return the list of colors provided by the color scheme as hexidecimal values (e.g. #c0ffee).
        """
        raise NotImplementedError()


@dataclass(frozen=True)
class SingleColorScheme(ColorScheme):
    """
    A color scheme containing a single color.
    """
    color: str = DEFAULT_COLOR
    
    def get_colors(self) -> List[str]:
        colors = [self.color]
        return list(map(util.get_hex_color_value, colors))
    
    
@dataclass(frozen=True)
class DiffColorScheme(ColorScheme):
    """
    A color scheme that represents the difference between two sets of data where:

    - `added_color`: color for newly added items
    - `unchanged_color`: color for unchanged items
    - `removed_color`: color for removed items    
    """
    added_color: str = 'green'
    unchanged_color: str = 'yellow'
    removed_color: str = 'red'

    def get_colors(self) -> List[str]:
        colors = [self.removed_color, self.unchanged_color, self.added_color]
        return list(map(util.get_hex_color_value, colors))


@dataclass(frozen=True)
class GradientColorScheme(ColorScheme):
    """
    A color scheme that generates a gradient of colors between `min_color` and `max_color`.
    """
    min_color: str = 'green'
    max_color: str = 'red'
    
    def get_colors(self, min_value: int, max_value: int) -> List[str]:
        n = max_value - min_value + 1
        return util.get_color_gradient(self.min_color, self.max_color, n)
    
    def get_color_map(self, min_value: int, max_value: int) -> Dict[int, str]:
        m = {}
        colors = self.get_colors(min_value=min_value, max_value=max_value)
        for i, color in enumerate(colors, start=min_value):
            m[i] = color
        return m


@dataclass(frozen=True)
class LayerConfig:
    """
    The configuration that will be used when generating layers.
    """
    color_scheme: Optional[Union[SingleColorScheme, DiffColorScheme, GradientColorScheme]] = None
    disable_deselected_techniques: bool = False
    hide_disabled_techniques: bool = False
    hide_subtechniques: bool = True
    
    
def apply_layer_config(layer: Layer, layer_config: LayerConfig) -> Layer:    
    if layer_config.disable_deselected_techniques:
        layer = disable_deselected_techniques(layer)
    
    if layer_config.hide_disabled_techniques:
        layer = hide_disabled_techniques(layer)
    
    if layer_config.hide_subtechniques:
        layer = hide_subtechniques(layer)
    
    if layer_config.color_scheme:
        layer = apply_color_scheme(layer, layer_config.color_scheme)

    return layer


def drop_comments_from_layer(layer: Layer) -> Layer:
    for i, technique in enumerate(layer.techniques):
        if technique.comment:
            technique.comment = None
            layer.techniques[i] = technique
    return layer


def disable_deselected_techniques(layer: Layer) -> Layer:
    for i, technique in enumerate(layer.techniques):
        if not technique.enabled:
            if (not technique.color) and (technique.score is None):
                technique.enabled = False
                layer.techniques[i] = technique
    return layer


def hide_disabled_techniques(layer: Layer) -> Layer:
    layer.hideDisabled = True
    return layer


def hide_subtechniques(layer: Layer) -> Layer:
    for i, technique in enumerate(layer.techniques):
        if technique.showSubtechniques:
            technique.showSubtechniques = False
            layer.techniques[i] = technique
    return layer


def apply_color_scheme(layer: Layer, color_scheme: ColorScheme) -> Layer:
    if isinstance(color_scheme, SingleColorScheme):
        return apply_single_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, DiffColorScheme):
        return apply_diff_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, GradientColorScheme):
        return apply_gradient_color_scheme(layer, color_scheme)
    else:
        raise ValueError(f'Invalid color scheme: {color_scheme}')


def apply_single_color_scheme(layer: Layer, color_scheme: SingleColorScheme) -> Layer:
    techniques = layer.techniques
    for i, technique in enumerate(techniques):
        if technique.enabled:
            technique.color = color_scheme.color
            techniques[i] = technique
    return layer


def apply_diff_color_scheme(layer: Layer, color_scheme: DiffColorScheme) -> Layer:
    techniques = layer.techniques
    allowed = {-1, 0, 1}
    seen = {technique.score for technique in techniques}
    assert seen <= allowed, f'When applying a diff color scheme retroactively, scores must be in {allowed} - got {seen}'
    
    for i, technique in enumerate(techniques):
        if technique.score == -1:
            technique.color = color_scheme.removed_color
            techniques[i] = technique
        elif technique.score == 0:
            technique.color = color_scheme.unchanged_color
            techniques[i] = technique
        elif technique.score == 1:
            technique.color = color_scheme.added_color
            techniques[i] = technique
    return layer


def apply_gradient_color_scheme(layer: Layer, color_scheme: GradientColorScheme) -> Layer:
    techniques = layer.techniques
    scores = {technique.score for technique in techniques}
    min_score = min(scores)
    max_score = max(scores)
    color_map = color_scheme.get_color_map(min_score, max_score)
    
    for i, technique in enumerate(techniques):
        if technique.score in color_map:
            technique.color = color_map[technique.score]
            techniques[i] = technique
    return layer


@dataclass()
class STIX2DataSourceConfig:
    verify_tls_certificates: bool = True


@dataclass()
class STIX2ObjectFilter:
    include_revoked: bool = False
    include_deprecated: bool = False

    def matches(self, o: dict) -> bool:
        """
        Returns a boolean indicating whether or not the provided STIX 2 object matches the filter.
        """
        if not self.include_revoked and is_stix2_object_revoked(o):
            return False
        
        if not self.include_deprecated and is_stix2_object_deprecated(o):
            return False

        return True


def is_stix2_object_revoked(o: dict) -> bool:
    """
    Returns a boolean indicating whether or not the provided STIX 2 object has been revoked.
    """
    return o.get('revoked', False)


def is_stix2_object_deprecated(o: dict) -> bool:
    """
    Returns a boolean indicating whether or not the provided STIX 2 object has been deprecated.
    """
    return o.get('x_mitre_deprecated', False)


def parse_stix2_filter(query: str, delimeter: str = ' ') -> _STIX2Filter:
    """
    Parses the provided STIX 2 filter (e.g. 'type = attack-pattern') and returns a stix2.Filter object.
    """
    s, p, o = query.split(delimeter, maxsplit=2)
    return _STIX2Filter(s, p, o)


def get_mitre_attack_enterprise_data_source() -> DataSource:
    url = STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN[MITRE_ATTACK_ENTERPRISE]
    return get_stix2_data_source(url)


def get_mitre_attack_mobile_data_source() -> DataSource:
    url = STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN[MITRE_ATTACK_MOBILE]
    return get_stix2_data_source(url)


def get_mitre_attack_ics_data_source() -> DataSource:
    url = STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN[MITRE_ATTACK_ICS]
    return get_stix2_data_source(url)


# TODO: add support for S3
# TODO: add support for TAXII
# TODO: add support for filesystem sources
# TODO: add support for composite data sources
def get_stix2_data_source(path: str, config: Optional[STIX2DataSourceConfig] = None) -> DataSource:
    config = config or STIX2DataSourceConfig()
    if path.startswith(('http://', 'https://')):
        response = requests.get(path, verify=config.verify_tls_certificates)
        response.raise_for_status()

        data = response.json()
        src = MemorySource(data)
    else:
        data = util.read_json_file(path)
        src = MemorySource(data)
        
    return src


def iter_stix2_objects(src: DataSource, f: Optional[STIX2ObjectFilter] = None) -> Iterable[dict]:
    rows = src.query()
    if f:
        rows = filter(f.matches, rows)
    rows = map(convert_stix2_object_to_dict, rows)
    yield from rows


def convert_stix2_object_to_dict(o: Union[stix2.base._STIXBase, dict]) -> dict:
    if isinstance(o, stix2.base._STIXBase):
        o = json.loads(o.serialize(pretty=True))
    assert isinstance(o, dict)
    return o


# TODO: restrict auto-selected techniques to techniques from the MITRE ATT&CK framework (e.g., using x-mitre-matrix, x-mitre-tactic, attack-pattern objects).
def generate_layer(
    domain: str,
    data_source: Optional[DataSource] = None, 
    layer_config: Optional[LayerConfig] = None, 
    selected_techniques: Optional[Iterable[str]] = None, 
    objects_by_id: Optional[Dict[str, dict]] = None) -> Layer:
    """
    Generate a layer for the provided ATT&CK domain.
    
    - `domain`: the ATT&CK domain to generate the layer for (e.g., 'enterprise-attack', 'mobile-attack', 'ics-attack')
    - `data_source`: the STIX 2 data source to use when querying for ATT&CK objects (optional, a default data source will be used if not provided)
    - `layer_config`: the configuration to apply when generating the layer (optional, default configuration will be used if not provided)
    - `selected_techniques`: the techniques to include in the layer (optional, all techniques will be included if not provided)
    - `objects_by_id`: a dictionary of STIX 2 objects indexed by their ID (optional, used for caching).
    """
    layer_config = layer_config or LayerConfig()
    selected_techniques = selected_techniques or []
    
    if not data_source:
        url = STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN[url]
        data_source = get_stix2_data_source(url)
    
    if not objects_by_id:
        objects_by_id = {o['id']: o for o in data_source.query([_STIX2Filter('type', '=', 'attack-pattern')])}

    attack_patterns = [o for o in objects_by_id.values() if o['type'] == 'attack-pattern']
    
    layer = Layer(
        domain=domain,
        hideDisabled=layer_config.hide_disabled_techniques,
    )
    
    all_technique_ids = {extract_external_id(technique) for technique in attack_patterns}
    selected_techniques = set(map(str.upper, selected_techniques))

    for technique in selected_techniques:
        technique = Technique(
            techniqueID=technique,
            color=layer_config.color_scheme.color,
            showSubtechniques=not layer_config.hide_subtechniques,
        )
        layer.techniques.append(technique)
    
    if layer_config.disable_deselected_techniques:
        for technique in all_technique_ids - selected_techniques:
            technique = Technique(
                techniqueID=technique,
                enabled=False,
            )
            layer.techniques.append(technique)

    return layer


def generate_enterprise_layer(selected_techniques: Optional[List[str]] = None, layer_config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_ENTERPRISE, selected_techniques=selected_techniques, layer_config=layer_config)


def generate_mobile_layer(selected_techniques: Optional[List[str]] = None, config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_MOBILE, selected_techniques=selected_techniques, layer_config=config)


def generate_ics_layer(selected_techniques: Optional[List[str]] = None, config: Optional[LayerConfig] = None) -> Layer:
    return generate_layer(domain=MITRE_ATTACK_ICS, selected_techniques=selected_techniques, layer_config=config)


def read_layer(path: str) -> Layer:
    data = util.read_json_file(path)
    return parse_layer_from_dict(data)


def write_layer(layer: Layer, path: str):
    data = serialize_layer_to_dict(layer)
    with open(path, 'w') as f:
        json.dump(data, f, cls=util.JSONEncoder, indent=JSON_INDENT)


def parse_layer_from_dict(o: dict) -> Layer:
    return dacite.from_dict(Layer, o)


# TODO: apply layer config
def parse_layers_from_technique_list(techniques: Iterable[dict], layer_config: Optional[LayerConfig] = None) -> Layer:
    layer = Layer()
    for technique in techniques:
        technique = Technique(
            techniqueID=technique['technique_id'],
            tactic=technique.get('tactic'),
            color=technique.get('color'),
            score=technique.get('score'),
            comment=technique.get('comment'),
            enabled=technique.get('enabled', True),
        )
        layer.techniques.append(technique)
    
    if layer_config:
        layer = apply_layer_config(layer, layer_config)
    return layer


def serialize_layer_to_dict(layer: Layer) -> dict:
    data = dataclasses.asdict(layer)
    data = util.prune_dict(data)
    return data


def serialize_layer_to_json(layer: Layer, indent: int = JSON_INDENT) -> str:
    data = serialize_layer_to_dict(layer)
    return json.dumps(data, cls=util.JSONEncoder, indent=indent)


# TODO: merge layers as a heatmap
def merge_layers(layers: Iterable[Layer], merge_strategy: str = UNION) -> Layer:
    layers = list(layers)
    domains = {layer.domain for layer in layers}
    assert len(domains) == 1, f'Cannot merge layers from different domains: {domains}'
    
    if merge_strategy == HEATMAP:
        layer = merge_layers_as_heatmap(layers)        
    else:
        raise ValueError(f'Invalid merge strategy: {merge_strategy}')
    
    return layer


# TODO: make color scheme configurable
def merge_layers_as_heatmap(layers: List[Layer]) -> Layer:
    scores = collections.defaultdict(int)
    
    for layer in layers:
        seen = set()
        for technique in layer.techniques:
            technique_id = technique.techniqueID
            if technique_id not in seen:
                scores[technique_id] += 1
                seen.add(technique_id)
    
    min_score = 1
    max_score = max(scores.values())
    gradient = GradientColorScheme(
        min_color='cornflowerblue',
        max_color='darkblue',
    )
    color_map = gradient.get_color_map(min_value=min_score, max_value=max_score)
    
    techniques = []
    for technique_id, score in scores.items():
        color = color_map[score] if score >= min_score else None
        technique = Technique(
            techniqueID=technique_id,
            score=score,
            color=color,
        )
        techniques.append(technique)

    return Layer(
        gradient=Gradient(
            minValue=min_score,
            maxValue=max_score,
            colors=list(color_map.values()),
        ),
        techniques=techniques,
    )


def extract_external_id(o: dict) -> Optional[str]:
    for ref in o.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
