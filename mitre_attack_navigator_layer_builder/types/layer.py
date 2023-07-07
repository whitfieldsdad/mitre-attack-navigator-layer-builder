from typing import List, Optional, Union
from mitre_attack_navigator_layer_builder.color_schemes import get_hex_color_name
from mitre_attack_navigator_layer_builder.constants import (
    AVG,
    LAYOUT_AGGREGATE_FUNCTIONS,
    LAYOUT_TYPES,
    MITRE_ATTACK_ENTERPRISE,
    SIDE,
    SORT_ASCENDING_BY_TECHNIQUE_NAME,
)
import mitre_attack_navigator_layer_builder.resolver as resolver

from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)


class Link(BaseModel):
    label: str
    url: str


class LegendItem(BaseModel):
    label: str
    color: str


class MetadataItem(BaseModel):
    name: str
    value: str


class Divider(BaseModel):
    divider: bool = True


class Gradient(BaseModel):
    colors: List[str]
    minValue: int = 0
    maxValue: int = 100

    @property
    def min_value(self) -> int:
        return self.minValue

    @property
    def max_value(self) -> int:
        return self.maxValue


class Technique(BaseModel):
    techniqueID: str
    tactic: Optional[str] = None
    enabled: Optional[bool] = True
    score: Optional[int] = None
    metadata: List[Union[MetadataItem, Divider]] = []
    color: Optional[str] = None
    comment: Optional[str] = None
    links: List[Union[Link, Divider]] = []
    showSubtechniques: bool = False

    @property
    def id(self) -> str:
        return self.techniqueID

    @property
    def technique_id(self) -> str:
        return self.techniqueID

    @property
    def color_name(self) -> Optional[str]:
        return get_hex_color_name(self.color)

    @property
    def hidden(self) -> bool:
        return not self.enabled

    @property
    def show_subtechniques(self) -> bool:
        return self.showSubtechniques


class Versions(BaseModel):
    attack: Optional[str] = None
    navigator: str = "4.8.0"
    layer: str = "4.4"


class Filter(BaseModel):
    platforms: List[str] = []


class Layout(BaseModel):
    layout: str = SIDE
    showID: bool = False
    showName: bool = True
    showAggregateScores: bool = False
    countUnscored: bool = False
    aggregateFunction: str = AVG

    def __post_init__(self):
        for attr, allowed_values in [
            ("aggregateFunction", LAYOUT_AGGREGATE_FUNCTIONS),
            ("layout", LAYOUT_TYPES),
        ]:
            value = getattr(self, attr)
            if value not in allowed_values:
                raise ValueError(
                    f"{attr} must be one of {allowed_values} - not `{value}`"
                )

    @property
    def show_id(self) -> bool:
        return self.showID

    @property
    def show_name(self) -> bool:
        return self.showName

    @property
    def show_aggregate_scores(self) -> bool:
        return self.showAggregateScores

    @property
    def count_unscored(self) -> bool:
        return self.countUnscored

    @property
    def aggregate_function(self) -> str:
        return self.aggregateFunction


class Layer(BaseModel):
    name: str
    versions: Optional[Versions] = None
    domain: Optional[str] = MITRE_ATTACK_ENTERPRISE
    customDataURL: Optional[str] = None
    description: Optional[str] = None
    filters: Optional[Filter] = None
    sorting: Optional[int] = SORT_ASCENDING_BY_TECHNIQUE_NAME
    layout: Optional[Layout] = None
    hideDisabled: bool = False
    techniques: List[Technique] = []
    gradient: Optional[Gradient] = None
    legendItems: List[LegendItem] = None
    showTacticRowBackground: bool = False
    tacticRowBackground: str = "# dddddd"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = True
    metadata: List[Union[MetadataItem, Divider]] = []

    @property
    def custom_data_url(self) -> Optional[str]:
        return self.customDataURL

    @property
    def tactic_row_background(self) -> str:
        return self.tacticRowBackground

    @property
    def show_tactic_row_background(self) -> bool:
        return self.showTacticRowBackground

    @property
    def hide_disabled(self) -> bool:
        return self.hideDisabled

    @property
    def select_techniques_across_tactics(self) -> bool:
        return self.selectTechniquesAcrossTactics

    @property
    def select_subtechniques_with_parent(self) -> bool:
        return self.selectSubtechniquesWithParent

    @property
    def legend_items(self) -> List[LegendItem]:
        return self.legendItems

    def disable_selected_techniques(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if technique.color and technique.enabled:
                logger.debug(f"Disabling {technique.technique_id}")
                self.techniques[i].enabled = False
        return self

    def disable_deselected_techniques(self) -> "Layer":
        # Disable any techniques not included in the layer.
        all_technique_ids = resolver.get_mitre_attack_technique_ids(self.domain)
        techniques_in_layer = [technique.technique_id for technique in self.techniques]

        logger.info("Disabling techniques not included in the layer...")
        total = 0
        for technique_id in all_technique_ids:
            if technique_id not in techniques_in_layer:
                technique = Technique(techniqueID=technique_id, enabled=False)
                self.techniques.append(technique)
                total += 1

        logger.info(f"Disabled {total} technique{'s' if total != 1 else ''}")

        # Disable any techniques that don't have a colour assigned if other techniques have colours assigned.
        if any(technique.color for technique in self.techniques):
            logger.info("Disabling techniques without colours assigned...")
            total = 0
            for i, technique in enumerate(self.techniques):
                if not technique.color and technique.enabled:
                    self.techniques[i].enabled = False
                    total += 1

            logger.info(f"Disabled {total} technique{'s' if total != 1 else ''}")
        return self

    def expand_subtechniques(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if not technique.showSubtechniques:
                self.techniques[i].showSubtechniques = True
        return self

    def collapse_subtechniques(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if technique.showSubtechniques:
                self.techniques[i].showSubtechniques = False
        return self

    def remove_descriptions(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if technique.comment:
                self.techniques[i].comment = None
        return self

    def remove_colors(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if technique.color:
                self.techniques[i].color = None
        return self
