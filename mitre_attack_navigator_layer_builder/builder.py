import collections
from dataclasses import dataclass
import sys
import dacite
from stix2 import TAXIICollectionSource
from stix2.base import _STIXBase
from stix2.datastore import DataSource, DataStoreMixin, DataSourceError
from stix2.datastore.filesystem import FileSystemSource
from stix2.datastore.filters import Filter as STIX2Filter
from stix2.datastore.memory import MemoryStore, MemorySource
from taxii2client.v21 import Collection
from typing import Any, Dict, Iterable, Iterator, Optional, Union, List
import concurrent.futures
import dataclasses
import json
import os
import requests
import urllib.parse
import uuid

from mitre_attack_navigator_layer_builder.constants import DEFAULT_COLOR, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE
from mitre_attack_navigator_layer_builder.layers import Gradient, Layer, Technique
from mitre_attack_navigator_layer_builder.util import JSONEncoder
from mitre_attack_navigator_layer_builder import util
from mitre_attack_navigator_layer_builder.layers import read_layer, write_layer


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
    
    def get_colors(self, max_value: int) -> List[str]:
        return util.get_color_gradient(self.min_color, self.max_color, max_value)
    
    def get_color_map(self, max_value: int) -> Dict[int, str]:
        m = {}
        colors = self.get_colors(max_value=max_value)
        for i, color in enumerate(colors, start=1):
            m[i] = color
        return m


@dataclass(frozen=True)
class LayerConfig:
    """
    The configuration that will be used when generating layers.
    """
    color_scheme: Optional[Union[str, SingleColorScheme, DiffColorScheme, GradientColorScheme]] = None
    disable_deselected_techniques: bool = False
    hide_disabled_techniques: bool = False
    hide_subtechniques: bool = True
    reset_technique_scores: bool = False
    drop_comments: bool = False


def generate_enterprise_layer(
    data_source: DataSource,
    technique_ids: Optional[Iterable[str]] = None,
    config: Optional[LayerConfig] = None) -> Layer:

    return generate_layer(
        data_source=data_source,
        domain=MITRE_ATTACK_ENTERPRISE,
        technique_ids=technique_ids,
        config=config
    )


def generate_mobile_layer(
    data_source: DataSource,
    technique_ids: Optional[Iterable[str]] = None,
    config: Optional[LayerConfig] = None) -> Layer:

    return generate_layer(
        data_source=data_source,
        domain=MITRE_ATTACK_MOBILE,
        technique_ids=technique_ids,
        config=config
    )
    
    
def generate_ics_layer(
    data_source: DataSource,
    technique_ids: Optional[Iterable[str]] = None,
    config: Optional[LayerConfig] = None) -> Layer:

    return generate_layer(
        data_source=data_source,
        domain=MITRE_ATTACK_ICS,
        technique_ids=technique_ids,
        config=config
    )

    
# TODO
def generate_layer(
    data_source: DataSource,
    domain: str,
    technique_ids: Optional[Iterable[str]] = None,
    config: Optional[LayerConfig] = None) -> Layer:
    """
    Generate a layer from the provided techniques and domain.
    """
    layer = Layer(
        domain=domain
    )
    
    if technique_ids:
        for technique_id in technique_ids:
            technique = Technique(
                techniqueID=technique_id,
                enabled=True,
                color=DEFAULT_COLOR,
            )
            layer.techniques.append(technique)
    
    if config:
        if config.disable_deselected_techniques:
            selected_techniques = {technique.techniqueID for technique in layer.techniques}
            
            # TODO: here
            all_techniques = {parse_external_id(o) for o in data_source.query([STIX2Filter('type', '=', 'attack-pattern')])}
            deselected_techniques = all_techniques - selected_techniques
            for technique_id in deselected_techniques:
                technique = Technique(
                    techniqueID=technique_id,
                    enabled=False,
                )
                layer.techniques.append(technique)

        layer = apply_layer_config(layer=layer, config=config)
    return layer


# TODO
def apply_layer_config(layer: Layer, config: LayerConfig) -> Layer:
    """
    Apply the provided layer configuration to the provided layer.
    """
    if config.disable_deselected_techniques:
        layer = disable_deselected_techniques(layer)
    
    if config.hide_disabled_techniques:
        layer = hide_disabled_techniques(layer)
    
    if config.hide_subtechniques is not None:
        layer = toggle_subtechnique_visibility(layer, visible=not config.hide_subtechniques)
    
    if config.color_scheme:
        layer = apply_color_scheme(layer, config.color_scheme)
        
    if config.reset_technique_scores:
        layer = reset_technique_scores(layer)
        
    if config.drop_comments:
        layer = drop_comments_from_layer(layer)

    return layer


# TODO
def drop_comments_from_layer(layer: Layer) -> Layer:
    """
    Drop any technique comments from the provided layer.
    """
    for i, technique in enumerate(layer.techniques):
        if technique.comment:
            technique.comment = None
            layer.techniques[i] = technique
    return layer


# TODO
def disable_deselected_techniques(layer: Layer) -> Layer:
    """
    Disable any enabled techniques that either have no color or no score.
    """
    for i, technique in enumerate(layer.techniques):
        if not technique.enabled:
            if (not technique.color) and (technique.score is None):
                technique.enabled = False
                layer.techniques[i] = technique
    return layer


# TODO
def reset_technique_scores(layer: Layer) -> Layer:
    """
    Reset the scores of the techniques in the provided layer.
    """
    for i, technique in enumerate(layer.techniques):
        technique.score = None
        layer.techniques[i] = technique
    return layer


# TODO
def hide_disabled_techniques(layer: Layer) -> Layer:
    """
    Hide disabled techniques in the provided layer.
    """
    layer.hideDisabled = True
    return layer


def show_subtechniques(layer: Layer) -> Layer:
    return toggle_subtechnique_visibility(layer, visible=True)


def hide_subtechniques(layer: Layer) -> Layer:
    return toggle_subtechnique_visibility(layer, visible=False)


def toggle_subtechnique_visibility(layer: Layer, visible: bool) -> Layer:
    for i, technique in enumerate(layer.techniques):
        technique.showSubtechniques = visible
        layer.techniques[i] = technique
    return layer


# TODO
def merge_layers_as_heatmap(layers: List[Layer]) -> Layer:
    domains = {layer.domain for layer in layers}
    assert len(domains) == 1, f'All layers must have the same domain - got {domains}'
    
    technique_scores = collections.defaultdict(int)
    for layer in layers:
        for technique in layer.techniques:
            if technique.enabled:
                technique_scores[technique.id] += 1
    
    max_score = max(technique_scores.values())
    color_scheme = GradientColorScheme()
    color_map = color_scheme.get_color_map(max_score)

    layer = Layer(
        domain=next(iter(domains)),
        gradient=Gradient(
            minValue=1,
            maxValue=max_score,
            colors=list(color_map.values()),
        )
    )
    for technique, score in technique_scores.items():
        technique = Technique(
            techniqueID=technique, 
            score=score, 
            color=color_map[score],
        )
        layer.techniques.append(technique)
    
    return layer


def apply_color_scheme(layer: Layer, color_scheme: Union[str, ColorScheme]) -> Layer:
    """
    Apply the provided color scheme to the provided layer.
    """
    if isinstance(color_scheme, str):
        return apply_single_color_scheme(layer, SingleColorScheme(color_scheme))
    elif isinstance(color_scheme, SingleColorScheme):
        return apply_single_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, DiffColorScheme):
        return apply_diff_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, GradientColorScheme):
        return apply_gradient_color_scheme(layer, color_scheme)
    else:
        raise ValueError(f'Invalid color scheme: {color_scheme}')


# TODO
def apply_single_color_scheme(layer: Layer, color_scheme: SingleColorScheme) -> Layer:
    """
    Apply the provided single color scheme to the provided layer.
    """
    techniques = layer.techniques
    for i, technique in enumerate(techniques):
        if technique.enabled:
            technique.color = color_scheme.color
            techniques[i] = technique
    return layer


# TODO
def apply_diff_color_scheme(layer: Layer, color_scheme: DiffColorScheme) -> Layer:
    """
    Apply the provided diff color scheme to the provided layer.
    """
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


# TODO
def apply_gradient_color_scheme(layer: Layer, color_scheme: GradientColorScheme) -> Layer:
    """
    Apply the provided gradient color scheme to the provided layer.
    """
    techniques = layer.techniques
    scores = {technique.score for technique in techniques}
    min_score = min(scores)
    max_score = max(scores)
    color_map = color_scheme.get_color_map(max_score)
    
    for i, technique in enumerate(techniques):
        if technique.score in color_map:
            technique.color = color_map[technique.score]
            techniques[i] = technique
    return layer


@dataclass()
class Neo4jDataSourceConfig:
    url: str


@dataclass()
class Neo4jDataStore(DataStoreMixin):
    """
    A STIX 2 data store that allows you to persist STIX 2 objects to a Neo4j database.
    """
    config: Neo4jDataSourceConfig = dataclasses.field(default_factory=Neo4jDataSourceConfig)
    
    def get(self, stix_id: str) -> Optional[dict]:
        raise NotImplementedError()
    
    def add(self, rows: Iterable[dict]) -> None:
        raise NotImplementedError()

    def all_versions(self, stix_id: str) -> Iterator[dict]:
        raise NotImplementedError()
    
    def query(self, query: List[STIX2Filter] = None) -> Iterator[dict]:
        raise NotImplementedError()
    

@dataclass(frozen=True)
class Decoder:
    """
    A decoder that can be used to determine if a STIX 2 object is revoked or deprecated.
    """
    def is_revoked(self, o: dict) -> bool:
        """
        Determine if the provided STIX 2 object is revoked.
        """
        raise NotImplementedError()
    
    def is_deprecated(self, o: dict) -> bool:
        """
        Determine if the provided STIX 2 object is deprecated.
        """
        raise NotImplementedError()


@dataclass(frozen=True)
class MitreDecoder:
    def is_revoked(self, o: dict) -> bool:
        return o.get('revoked', False)
    
    def is_deprecated(self, o: dict) -> bool:
        return o.get('x-mitre-deprecated', False)


def parse_external_id(o: dict) -> Optional[str]:
    """
    Parse the external ID of the provided STIX 2 object.
    """
    if is_mitre_attack_object(o):
        return next((ref['external_id'] for ref in o['external_references'] if ref['source_name'] == 'mitre-attack'), None)
    elif is_mitre_capec_object(o):
        return next((ref['external_id'] for ref in o['external_references'] if ref['source_name'] == 'capec'), None)
    elif is_mitre_mbc_object(o):
        if 'obj_defn' in o:
            return o['obj_defn']['external_id']
    elif is_nist_sp_800_53_object(o):
        for ref in o['external_references']:
            if ref['source_name'] in ['NIST 800-53 Revision 4', 'NIST 800-53 Revision 5']:
                return ref['external_id']


def is_mitre_attack_object(o: dict) -> bool:
    """
    Determine if the provided STIX 2 object is from the Mitre Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) dataset.
    """
    if o:
        marking = 'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'
        return o['id'] == marking or marking in o['object_marking_refs']
    return False


def is_mitre_capec_object(o: dict) -> bool:
    """
    Determine if the provided STIX 2 object is from the Mitre Common Attack Pattern Enumeration and Classification (CAPEC) dataset.
    """
    if o:
        marking = 'marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d'
        return o['id'] == marking or marking in o['object_marking_refs']
    return False


def is_mitre_mbc_object(o: dict) -> bool:
    """
    Determine if the provided STIX 2 object is from the Mitre Malware Behavior Catalog (MBC).
    """
    if not o:
        return False
    
    identity = 'identity--b73c59c1-8560-449a-b8d0-c2ce0533c5bf'
    marking = 'marking-definition--f88d90b2-8e23-4f1d-9b4c-4ab3c4a3e2b7'
    if o['id'] == marking or marking in o.get('object_marking_refs', []):
        return True
    elif o['id'] == identity or o.get('created_by_ref') == identity:
        return True
    else:
        return False
    

def is_nist_sp_800_53_object(o: dict) -> bool:
    """
    Determine if the provided STIX 2 object represents a control or subcontrol from NIST Special Publication 800-53 Revision 4 or 5.
    """
    for ref in o.get('external_references', []):
        if ref['source_name'] in ['NIST 800-53 Revision 4', 'NIST 800-53 Revision 5']:
            return True
    return False


def iter_stix2_objects(
    data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]], 
    queries: Optional[Iterable[str]] = None, 
    include_deprecated_objects: bool = False, 
    include_revoked_objects: bool = False) -> Iterator[dict]:
    """
    Given the provided STIX 2 data sources, queries, and filters, return an iterator of STIX 2 objects.
    """
    if isinstance(data_sources, (str, DataSource)):
        data_sources = [data_sources]
            
    if queries:
        queries = [parse_stix2_filter(q) if isinstance(q, str) else STIX2Filter for q in queries]
    
    decoder = MitreDecoder()
    for src in data_sources:
        src = get_stix2_data_source(src) if isinstance(src, str) else src
        rows = src.query(queries)
        rows = map(parse_stix2_object, rows)

        if include_deprecated_objects is False:
            rows = filter(lambda o: decoder.is_deprecated(o) is False, rows)
        
        if include_revoked_objects is False:
            rows = filter(lambda o: decoder.is_revoked(o) is False, rows)

        yield from rows


def parse_stix2_object(o: Union[_STIXBase, dict]) -> dict:
    """
    Convert the provided STIX 2 object from a STIX object to a dictionary.
    """
    if isinstance(o, _STIXBase):
        o = json.loads(o.serialize(pretty=True))
    assert isinstance(o, dict)
    return o


def parse_stix2_filter(s: str) -> STIX2Filter:
    """
    Parse the provided STIX 2 filter (e.g. "type = 'attack-pattern'") into a STIX 2 filter object.
    """
    s, p, o = s.split(' ', maxsplit=2)
    return STIX2Filter(s, p, o)


def get_stix2_data_sources(data_sources: Iterable[Union[str, DataSource]]) -> List[DataSource]:
    """
    Given the provided iterable of STIX 2 data sources, file paths, and URLs, return a list of STIX 2 data sources.
    """
    return list(map(get_stix2_data_source, data_sources))


def get_stix2_data_source(path: str, memory: bool = True) -> Union[DataSource, MemoryStore]:
    """
    Given the provided file path or URL, return a STIX 2 data source.
    """
    if path.startswith(('http://', 'https://')):
        return get_stix2_data_source_from_url(path)
    
    path = util.get_real_path(path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    elif os.path.isdir(path):
        return get_stix2_data_source_from_directory(path, memory=memory)
    elif os.path.isfile(path):
        return get_stix2_data_source_from_file(path)
    else:
        raise ValueError(f"Unsupported path: {path}")

    
def get_stix2_data_source_from_url(url: str, verify_tls_certificate_chain: bool = False) -> DataSource:
    """
    Given the provided URL, return a STIX 2 data source.
    """
    scheme, _, _, _, _, _ = urllib.parse.urlparse(url)
    if scheme in ('http', 'https'):
        try:
            return TAXIICollectionSource(Collection(url))
        except DataSourceError as e:
            response = requests.get(url, verify=verify_tls_certificate_chain)
            response.raise_for_status()
            data = response.json()
            return MemorySource(data)
    else:
        raise ValueError(f"Unsupported URL scheme: {url}")


def get_stix2_data_source_from_file(path: str) -> DataSource:
    """
    Given the provided file path, return a STIX 2 data source
    """
    store = MemoryStore()
    if path.endswith(('.json', '.json.gz')):
        bundle = util.read_json_file(path)
        for row in bundle['objects']:
            store.add(row)
    else:
        raise ValueError(f"Unsupported file format: {path}")
    return store


def get_stix2_data_source_from_directory(path: str, memory: bool = False) -> DataSource:
    """
    Given the provided directory path, return a STIX 2 data source.
    """
    if memory:
        def f(path: str) -> Iterator[dict]:
            yield from util.read_json_file(path)['objects']
        
        paths = set()
        for root, _, files in os.walk(path):
            for file in files:
                path = os.path.join(root, file)
                paths.add(path)
        
        memory_store = MemoryStore()
        with concurrent.futures.ThreadPoolExecutor() as executor:            
            for bundle in executor.map(f, paths):
                for row in bundle:
                    memory_store.add(row)

        return memory_store
    else:
        return FileSystemSource(path)


def read_stix2_bundle(path: str) -> Iterable[dict]:
    """
    Read the STIX 2 bundle from the specified file path.
    """
    src = get_stix2_data_source(path)
    yield from src.query()


def write_stix2_bundle(rows: Iterable[dict], path: str, indent: int = 4, spec_version: str = '2.1') -> None:
    """
    Write the provided STIX 2 bundle to the specified file path.
    """
    path = util.get_real_path(path)
    with open(path, mode='w') as fp:
        bundle = new_stix2_bundle(rows, spec_version=spec_version)
        json.dump(bundle, fp, cls=JSONEncoder, indent=indent)


def new_stix2_bundle(rows: Iterable[dict], spec_version: str = '2.1') -> dict:
    """
    Create a new STIX 2 bundle.
    """
    return {
        'id': f'bundle--{uuid.uuid4()}',
        'type': 'bundle',
        'spec_version': spec_version,
        'objects': list(rows),
    }
