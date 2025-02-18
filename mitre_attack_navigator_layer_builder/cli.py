from typing import List
from mitre_attack_navigator_layer_builder.builder import LayerConfig, STIX2ObjectFilter, SingleColorScheme
import click
import logging


@click.group()
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    
    

@main.command()
def generate_layer():
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


@main.command()
@click.option('--input-layers', '-i', type=str, multiple=True, help="Paths to input layers")
@click.option('--output-path', '-o', type=str, help="Path to output workbook")
def generate_xlsx_workbook(input_layers: List[str], output_path: str):
    raise NotImplementedError()


if __name__ == "__main__":
    main()
