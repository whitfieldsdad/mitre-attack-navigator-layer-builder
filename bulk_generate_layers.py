from typing import Dict, Iterator, List, Optional
from mitre_attack_navigator_layer_builder import builder
from mitre_attack_navigator_layer_builder.builder import LayerConfig, STIX2ObjectFilter, SingleColorScheme
from mitre_attack_navigator_layer_builder.layers import Layer

import logging
import urllib3
import os

from mitre_attack_navigator_layer_builder.constants import MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE

logging.basicConfig(level=logging.INFO)

# Disable TLS certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    stix2_object_filter = STIX2ObjectFilter(
        include_revoked=False,
        include_deprecated=False
    )
    layer_config = LayerConfig(
        color_scheme=SingleColorScheme(color='cornflowerblue'),
        disable_deselected_techniques=True,
        hide_disabled_techniques=True,
        hide_subtechniques=False,
    )
    for domain in [
        MITRE_ATTACK_ENTERPRISE, 
        MITRE_ATTACK_MOBILE, 
        MITRE_ATTACK_ICS
    ]:
        src = builder.get_stix2_data_source_by_mitre_attack_domain(domain)
        objects_by_id = {o['id']: o for o in builder.iter_stix2_objects(src, f=stix2_object_filter)}
        
        generators = {
            'intrusion_sets': generate_layers_for_mitre_attack_intrusion_sets,
            'malware_families': generate_layers_for_mitre_attack_malware_families,
            'tools': generate_layers_for_mitre_attack_tools,
            'mitigations': generate_layers_for_mitre_attack_mitigations,
        }
        for subdirectory, g in generators.items():
            output_dir = f'examples/layers/{domain}/{subdirectory}'
            os.makedirs(output_dir, exist_ok=True)
            
            for layer in g(domain=domain, objects_by_id=objects_by_id, layer_config=layer_config):
                output_path = os.path.join(output_dir, f'{layer.name}.json')
                builder.write_layer(layer, output_path)


def generate_layers_for_mitre_attack_intrusion_sets(domain: str, objects_by_id: Dict[str, dict], layer_config: LayerConfig) -> Iterator[Layer]: 
    relationships = [o for o in objects_by_id.values() if o['type'] == 'relationship']
    relationships = [o for o in relationships if o['source_ref'].startswith('intrusion-set') and o['target_ref'].startswith('attack-pattern')]
        
    for intrusion_set_id in {o['source_ref'] for o in relationships}:
        intrusion_set = objects_by_id[intrusion_set_id]
       
        technique_ids = {o['target_ref'] for o in relationships if o['source_ref'] == intrusion_set_id}
        techniques = {v for v in {builder.extract_external_id(objects_by_id[technique_id]) for technique_id in technique_ids} if v}
        if not techniques:
            continue
        
        layer = builder.generate_layer(
            domain=domain, 
            objects_by_id=objects_by_id,
            selected_techniques=techniques, 
            layer_config=layer_config,
        )
        layer.name = builder.extract_external_id(intrusion_set)
        layer.description = f'Techniques used by {intrusion_set["name"]}'
        yield layer
        

def generate_layers_for_mitre_attack_mitigations(domain: str, objects_by_id: Dict[str, dict], layer_config: LayerConfig) -> Iterator[Layer]:
    relationships = [o for o in objects_by_id.values() if o['type'] == 'relationship']
    relationships = [o for o in relationships if o['source_ref'].startswith('course-of-action') and o['target_ref'].startswith('attack-pattern')]
        
    for mitigation_id in {o['source_ref'] for o in relationships}:
        mitigation = objects_by_id[mitigation_id]
        
        technique_ids = {o['target_ref'] for o in relationships if o['source_ref'] == mitigation_id}
        techniques = {v for v in {builder.extract_external_id(objects_by_id[technique_id]) for technique_id in technique_ids} if v}
        if not techniques:
            continue
        
        layer = builder.generate_layer(
            domain=domain, 
            objects_by_id=objects_by_id,
            selected_techniques=techniques, 
            layer_config=layer_config,
        )
        layer.name = builder.extract_external_id(mitigation)
        layer.description = f'Techniques mitigated by {mitigation["name"]}'
        yield layer
        

def generate_layers_for_mitre_attack_malware_families(domain: str, objects_by_id: Dict[str, dict], layer_config: LayerConfig) -> Iterator[Layer]:
    relationships = [o for o in objects_by_id.values() if o['type'] == 'relationship']
    relationships = [o for o in relationships if o['source_ref'].startswith('malware') and o['target_ref'].startswith('attack-pattern')]

    for malware_id in {o['source_ref'] for o in relationships}:
        malware = objects_by_id[malware_id]
        
        technique_ids = {o['target_ref'] for o in relationships if o['source_ref'] == malware_id}
        techniques = {v for v in {builder.extract_external_id(objects_by_id[technique_id]) for technique_id in technique_ids} if v}
        if not techniques:
            continue
        
        layer = builder.generate_layer(
            domain=domain, 
            objects_by_id=objects_by_id,
            selected_techniques=techniques, 
            layer_config=layer_config,
        )
        layer.name = builder.extract_external_id(malware)
        layer.description = f'Techniques used by {malware["name"]}'
        yield layer
        
        
def generate_layers_for_mitre_attack_tools(domain: str, objects_by_id: Dict[str, dict], layer_config: LayerConfig) -> Iterator[Layer]:
    relationships = [o for o in objects_by_id.values() if o['type'] == 'relationship']
    relationships = [o for o in relationships if o['source_ref'].startswith('tool') and o['target_ref'].startswith('attack-pattern')]

    for tool_id in {o['source_ref'] for o in relationships}:
        tool = objects_by_id[tool_id]

        technique_ids = {o['target_ref'] for o in relationships if o['source_ref'] == tool_id}
        techniques = {v for v in {builder.extract_external_id(objects_by_id[technique_id]) for technique_id in technique_ids} if v}
        if not techniques:
            continue
        
        layer = builder.generate_layer(
            domain=domain, 
            objects_by_id=objects_by_id,
            selected_techniques=techniques, 
            layer_config=layer_config,
        )
        layer.name = builder.extract_external_id(tool)
        layer.description = f'Techniques used by {tool["name"]}'
        yield layer


if __name__ == "__main__":
    main()
