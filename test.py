import json
import sys
from mitre_attack_navigator_layer_builder import coloring, layers, io, util

import logging
import urllib3

from mitre_attack_navigator_layer_builder.coloring import IntersectionColorScheme, DiffColorScheme, LabeledColorScheme, SingleColorScheme, GradientColorScheme

logging.basicConfig(level=logging.DEBUG)

# Disable TLS certificate verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



def main():    
    single_color_scheme = SingleColorScheme(
        color='PaleGoldenrod',
    )
    heatmap_color_scheme = GradientColorScheme(
        min_color='PaleGoldenrod',
        max_color='FireBrick',
    )

    # Load data sources
    mitre_attack = io.get_stix2_data_source('~/src/attack-stix-data/enterprise-attack/enterprise-attack.json')
    attack_patterns = [o for o in io.iter_stix2_objects(mitre_attack) if o['type'] == 'attack-pattern']

    a = io.read_layer('examples/layers/oilrig.json')
    b = io.read_layer('examples/layers/muddywater.json')
    c = io.read_layer('examples/layers/fin7.json')

    a = layers.apply_single_color_scheme(a, single_color_scheme).disable_deselected_techniques()
    b = layers.apply_single_color_scheme(b, single_color_scheme).disable_deselected_techniques()
    c = layers.apply_single_color_scheme(c, single_color_scheme).disable_deselected_techniques()

    io.write_layer(a, 'examples/layers/oilrig.json')
    io.write_layer(b, 'examples/layers/muddywater.json')
    io.write_layer(c, 'examples/layers/fin7.json')

    o = layers.calculate_heatmap([a, b, c], color_scheme=heatmap_color_scheme).disable_deselected_techniques()
    layers.add_missing_techniques(o, attack_patterns, enable=False)

    io.write_layer(o, 'examples/layers/heatmap.json')



if __name__ == "__main__":
    main()
