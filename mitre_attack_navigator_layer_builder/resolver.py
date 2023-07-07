import glob
import os
from typing import Set
import requests
import stix2
from mitre_attack_navigator_layer_builder.constants import (
    LAYER_DOMAIN_NORMALIZATION_MAP,
    MITRE_ATTACK_ENTERPRISE,
    MITRE_ATTACK_ICS,
    MITRE_ATTACK_MOBILE,
)
import logging
import json

logger = logging.getLogger(__name__)


def read_stix2_content_from_github(
    domain: str, branch: str = "master"
) -> stix2.MemoryStore:
    domain = LAYER_DOMAIN_NORMALIZATION_MAP[domain]

    url = f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json"

    # Check the latest version.
    response = requests.head(url)
    response.raise_for_status()

    etag = response.headers["ETag"].replace('"', "").replace("W/", "")

    # Check the cache and perform cache eviction.
    latest_file = os.path.abspath(f"cache/{domain}-{etag}.json")
    for file in glob.glob(f"cache/{domain}-*.json"):
        file = os.path.abspath(file)
        if file != latest_file:
            try:
                os.remove(file)
            except OSError:
                continue

    # Read from the cache.
    if os.path.exists(latest_file) and os.path.getsize(latest_file) > 0:
        logger.info(f"Reading {domain} from cache: {latest_file}")
        src = stix2.MemoryStore()
        src.load_from_file(latest_file)
        return src

    logger.info(f"Fetching latest copy of {domain} from {url}")
    stix_json = requests.get(url).json()

    # Save a copy to the cache.
    os.makedirs("cache", exist_ok=True)
    with open(latest_file, "w") as file:
        json.dump(stix_json, file, indent=2)

    return stix2.MemoryStore(stix_data=stix_json)


def get_mitre_attack_technique_ids(domain: str) -> Set[str]:
    src = read_stix2_content_from_github(domain)
    techniques = src.query(
        [
            stix2.Filter("type", "=", "attack-pattern"),
        ]
    )
    technique_ids = set()
    for technique in techniques:
        for external_reference in technique.external_references:
            if external_reference.source_name == "mitre-attack":
                technique_ids.add(external_reference.external_id)
    return technique_ids


def get_mitre_attack_enterprise_technique_ids() -> Set[str]:
    return get_mitre_attack_technique_ids(MITRE_ATTACK_ENTERPRISE)


def get_mitre_attack_mobile_technique_ids() -> Set[str]:
    return get_mitre_attack_technique_ids(MITRE_ATTACK_MOBILE)


def get_mitre_attack_ics_technique_ids() -> Set[str]:
    return get_mitre_attack_technique_ids(MITRE_ATTACK_ICS)
