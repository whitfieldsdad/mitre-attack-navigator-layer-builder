from stix2.base import _STIXBase
from stix2.datastore.filters import Filter as STIX2Filter
from typing import Optional, Union
import json
from dataclasses import dataclass


@dataclass()
class Decoder:
    def get_external_id(self, o: dict) -> Optional[str]:
        return parse_external_id(o)
    
    def is_revoked(self, o: dict) -> bool:
        raise NotImplementedError()
    
    def is_deprecated(self, o: dict) -> bool:
        raise NotImplementedError()


@dataclass()
class MitreDecoder(Decoder):
    def is_revoked(self, o: dict) -> bool:
        return o.get('revoked', False)
    
    def is_deprecated(self, o: dict) -> bool:
        return o.get('x-mitre-deprecated', False)


def parse_stix2_object(o: Union[_STIXBase, dict]) -> dict:
    if isinstance(o, _STIXBase):
        o = json.loads(o.serialize(pretty=True))
    assert isinstance(o, dict)
    return o


def parse_stix2_filter(s: str) -> STIX2Filter:
    for c in '"', "'":
        s = s.replace(c, '')

    s = s.strip()
    s, p, o = s.split(' ', maxsplit=2)
    return STIX2Filter(s, p, o)


def parse_external_id(o: dict) -> Optional[str]:
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
    if o:
        marking = 'marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168'
        return o['id'] == marking or marking in o['object_marking_refs']
    return False


def is_mitre_capec_object(o: dict) -> bool:
    if o:
        marking = 'marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d'
        return o['id'] == marking or marking in o['object_marking_refs']
    return False


def is_mitre_mbc_object(o: dict) -> bool:
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
    for ref in o.get('external_references', []):
        if ref['source_name'] in ['NIST 800-53 Revision 4', 'NIST 800-53 Revision 5']:
            return True
    return False
