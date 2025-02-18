from dataclasses import dataclass
import dataclasses
from typing import List, Optional, Union
import polars as pl
import pandas as pd
import logging

from mitre_attack_navigator_layer_builder.constants import ATTACK_NAVIGATOR_LAYER_VERSION, ATTACK_NAVIGATOR_VERSION, AVG, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, NONE, SIDE, SORT_ASCENDING_BY_TECHNIQUE_NAME, STIX2_DATA_SOURCE_URLS_BY_MITRE_ATTACK_NAVIGATOR_LAYER_DOMAIN

logger = logging.getLogger(__name__)


@dataclass()
class Link:
    """
    A link that can be opened when hovering over the technique in the MITRE ATT&CK Navigator.
    """
    label: str
    url: str


@dataclass()
class LegendItem:
    label: str
    color: str


@dataclass()
class MetadataItem:
    name: str
    value: str


@dataclass()
class Divider:
    divider: bool = True


@dataclass()
class Gradient:
    minValue: int
    maxValue: int
    colors: List[str]
    
    def __post_init__(self):
        if len(self.colors) < 2:
            raise ValueError("Gradient must have at least two colors")

        if self.minValue >= self.maxValue:
            raise ValueError("minValue must be less than maxValue")


@dataclass()
class Technique:
    techniqueID: str
    tactic: Optional[str] = None
    enabled: Optional[bool] = True
    score: Optional[int] = None
    metadata: List[Union[MetadataItem, Divider]] = dataclasses.field(default_factory=list)
    color: Optional[str] = None
    comment: Optional[str] = None
    links: List[Union[Link, Divider]] = dataclasses.field(default_factory=list)
    showSubtechniques: bool = False


@dataclass()
class Versions:
    attack: Optional[str] = None
    navigator: str = ATTACK_NAVIGATOR_VERSION
    layer: str = ATTACK_NAVIGATOR_LAYER_VERSION


@dataclass()
class Filter:
    platforms: List[str] = dataclasses.field(default_factory=list)


@dataclass()
class Layout:
    layout: str = SIDE
    showID: bool = False
    showName: bool = True
    showAggregateScores: bool = False
    countUnscored: bool = False
    aggregateFunction: str = AVG
    expandedSubtechniques: str = NONE


@dataclass()
class Layer:
    name: str = "layer"
    description: str = ""
    versions: Optional[Versions] = dataclasses.field(default_factory=Versions)
    domain: str = MITRE_ATTACK_ENTERPRISE
    customDataURL: Optional[str] = None
    filters: Optional[Filter] = None
    hideDisabled: bool = False
    sorting: Optional[int] = SORT_ASCENDING_BY_TECHNIQUE_NAME
    layout: Optional[Layout] = None
    techniques: List[Technique] = dataclasses.field(default_factory=list)
    gradient: Optional[Gradient] = None
    legendItems: List[LegendItem] = dataclasses.field(default_factory=list)
    showTacticRowBackground: bool = False
    tacticRowBackground: str = "#dddddd"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = True
    selectVisibleTechniques: bool = False
    metadata: List[Union[MetadataItem, Divider]] = dataclasses.field(default_factory=list)
    links: List[Union[Link, Divider]] = dataclasses.field(default_factory=list)
 
    def __post_init__(self):
        self.description = self.description or ""
        assert self.domain in [MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_MOBILE, MITRE_ATTACK_ICS], f"Invalid domain: {self.domain}"

    def replace_color(self, old_color: str, new_color: str):
        found = False
        for technique in self.techniques:
            if technique.color == old_color:
                technique.color = new_color
                found = True

        if not found:
            raise ValueError(f"Color not found: {old_color}")
        
    def to_records(self) -> List[dict]:
        """
        Translate the layer into a list of records.
        
        Note: this method is lossy, and makes no attempt to preserve all information in the layer.
        """
        rows = []
        for technique in self.techniques:
            if technique.enabled:
                row = {
                    'tactic_id': technique.tactic,
                    'technique_id': technique.techniqueID,
                    'color': technique.color,
                    'score': technique.score,
                    'comment': technique.comment,
                    'enabled': technique.enabled,
                }
                rows.append(row)
        return rows
    
    def to_polars_dataframe(self) -> pl.DataFrame:
        return pl.DataFrame(self.to_records())
    
    def to_pandas_dataframe(self) -> pd.DataFrame:
        df = pd.DataFrame(self.to_records())
        return df
