from typing import Dict, List
import dacite
from stix2.datastore import DataSource
import collections
from stix2 import TAXIICollectionSource, Filter
from stix2.datastore import DataSource, DataSourceError, DataStoreMixin
from stix2.datastore.filesystem import FileSystemSource
from stix2.datastore.filters import Filter as STIX2Filter
from stix2.datastore.memory import MemoryStore, MemorySource
from taxii2client.v21 import Collection
from typing import Iterable, Iterator, Optional, Union, List
import concurrent.futures
import json
import os
import requests
import urllib.parse
import uuid

from mitre_attack_navigator_layer_builder.layers import Layer
from mitre_attack_navigator_layer_builder.util import JSONEncoder
from mitre_attack_navigator_layer_builder import parsers, util


def iter_stix2_objects(
    data_sources: Union[str, DataSource, DataStoreMixin, Iterable[Union[str, DataSource]]], 
    queries: Optional[Iterable[str]] = None, 
    include_deprecated_objects: bool = False, 
    include_revoked_objects: bool = False) -> Iterator[dict]:
    """
    Given the provided STIX 2 data sources, queries, and filters, return an iterator of STIX 2 objects.
    """
    if isinstance(data_sources, (str, MemoryStore, MemorySource, DataSource)):
        data_sources = [data_sources]
            
    if queries:
        queries = [parsers.parse_stix2_filter(q) if isinstance(q, str) else STIX2Filter for q in queries]
    
    decoder = parsers.MitreDecoder()
    for src in data_sources:
        src = get_stix2_data_source(src) if isinstance(src, str) else src
        rows = src.query(queries)
        rows = map(parsers.parse_stix2_object, rows)

        if include_deprecated_objects is False:
            rows = filter(lambda o: decoder.is_deprecated(o) is False, rows)
        
        if include_revoked_objects is False:
            rows = filter(lambda o: decoder.is_revoked(o) is False, rows)

        yield from rows


def get_stix2_data_sources(data_sources: Iterable[Union[str, DataSource]]) -> List[DataSource]:
    return list(map(get_stix2_data_source, data_sources))


def get_stix2_data_source(path: str, memory: bool = True) -> Union[DataSource, MemoryStore]:
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
    store = MemoryStore()
    if path.endswith(('.json', '.json.gz')):
        bundle = util.read_json_file(path)
        for row in bundle['objects']:
            store.add(row)
    else:
        raise ValueError(f"Unsupported file format: {path}")
    return store


def get_stix2_data_source_from_directory(path: str, memory: bool = False) -> DataSource:
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
    src = get_stix2_data_source(path)
    yield from src.query()


def write_stix2_bundle(rows: Iterable[dict], path: str, indent: int = 4, spec_version: str = '2.1') -> None:
    path = util.get_real_path(path)
    with open(path, mode='w') as fp:
        bundle = new_stix2_bundle(rows, spec_version=spec_version)
        json.dump(bundle, fp, cls=JSONEncoder, indent=indent)


def new_stix2_bundle(rows: Iterable[dict], spec_version: str = '2.1') -> dict:
    return {
        'id': f'bundle--{uuid.uuid4()}',
        'type': 'bundle',
        'spec_version': spec_version,
        'objects': list(rows),
    }


def get_map_of_attack_tactic_ids_to_technique_ids(data_source: DataSource) -> Dict[str, List[str]]:
    techniques = list(map(dict, data_source.query(Filter("type", "=", "attack-pattern"))))
    tactics = list(map(dict, data_source.query(Filter("type", "=", "x-mitre-tactic"))))
    
    tactic_shortnames_to_ids = {}
    for tactic in tactics:
        shortname = tactic['x_mitre_shortname']
        external_id = next(ref['external_id'] for ref in tactic['external_references'] if ref['source_name'] == 'mitre-attack')
        tactic_shortnames_to_ids[shortname] = external_id
    
    tactic_ids_to_technique_ids = collections.defaultdict(set)
    for technique in techniques:
        for phase in technique['kill_chain_phases']:
            tactic_id = tactic_shortnames_to_ids[phase['phase_name']]
            tactic_ids_to_technique_ids[tactic_id].add(tactic_id)

    return {k: sorted(v) for k, v in tactic_ids_to_technique_ids.items()}
    

def get_map_of_attack_technique_ids_to_tactic_ids(data_source: DataSource) -> Dict[str, List[str]]:
    m = collections.defaultdict(list)
    for tactic_id, technique_ids in get_map_of_attack_tactic_ids_to_technique_ids(data_source).items():
        for technique_id in technique_ids:
            m[technique_id].append(tactic_id)
    return dict(m)



def read_layer(path: str) -> Layer:
    path = util.get_real_path(path)
    o = util.read_json_file(path)
    return dacite.from_dict(data_class=Layer, data=o)



# TODO: add support for CSV
def write_layer(layer: Layer, path: str, indent: int = 4) -> None:
    data = util.prune_dict(layer.__dict__())

    path = util.get_real_path(path)

    if path.endswith('.json'):
        with open(path, mode='w') as fp:
            json.dump(data, fp, cls=JSONEncoder, indent=indent)
    else:
        raise ValueError(f"Unsupported file extension: {path}")
