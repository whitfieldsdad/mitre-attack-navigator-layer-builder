from typing import List
import click
import logging

from mitre_attack_navigator_layer_builder.constants import DEFAULT_COLOR, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, STIX2_URLS_BY_LAYER_DOMAIN


@click.group('main')
def main_group():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


if __name__ == "__main__":
    main_group()
