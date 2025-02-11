import dataclasses
from dataclasses import dataclass
from typing import List, Optional, Union
import logging

from mitre_attack_navigator_layer_builder.constants import ATTACK_NAVIGATOR_LAYER_VERSION, ATTACK_NAVIGATOR_VERSION, AVG, MITRE_ATTACK_ENTERPRISE, NONE, SIDE, SORT_ASCENDING_BY_TECHNIQUE_NAME

logger = logging.getLogger(__name__)


@dataclass()
class Link:
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
    colors: List[str]
    minValue: int = 0
    maxValue: int = 100
    
    def __post_init__(self):
        if len(self.colors) < 2:
            raise ValueError("Gradient must have at least two colors")

        if self.minValue >= self.maxValue:
            raise ValueError("minValue must be less than maxValue")
        
        if self.minValue < 0:
            raise ValueError("minValue must be greater than or equal to 0")
        
        if self.maxValue > 100:
            raise ValueError("maxValue must be less than or equal to 100")


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
    versions: Optional[Versions] = dataclasses.field(default_factory=Versions)
    domain: Optional[str] = MITRE_ATTACK_ENTERPRISE
    customDataURL: Optional[str] = None
    description: Optional[str] = None
    filters: Optional[Filter] = None
    sorting: Optional[int] = SORT_ASCENDING_BY_TECHNIQUE_NAME
    layout: Optional[Layout] = None
    hideDisabled: bool = False
    techniques: List[Technique] = dataclasses.field(default_factory=list)
    gradient: Optional[Gradient] = None
    legendItems: List[LegendItem] = None
    showTacticRowBackground: bool = False
    tacticRowBackground: str = "# dddddd"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = True
    selectVisibleTechniques: bool = False
    metadata: List[Union[MetadataItem, Divider]] = dataclasses.field(default_factory=list)
    links: List[Union[Link, Divider]] = dataclasses.field(default_factory=list)
