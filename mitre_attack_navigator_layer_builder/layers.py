from dataclasses import dataclass
import dataclasses
import json
from typing import Iterator, List, Optional, Set, Union
import logging

import dacite

from mitre_attack_navigator_layer_builder import util
from mitre_attack_navigator_layer_builder.util import JSONEncoder
from mitre_attack_navigator_layer_builder.constants import ATTACK_NAVIGATOR_LAYER_VERSION, ATTACK_NAVIGATOR_VERSION, AVG, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, MITRE_ATTACK_TACTIC_SHORTNAMES_TO_EXTERNAL_IDS, MITRE_ATTACK_TACTIC_SHORTNAMES_TO_NAMES, NONE, SIDE, SORT_ASCENDING_BY_TECHNIQUE_NAME

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
    
    @property
    def id(self) -> str:
        return self.techniqueID
    
    def is_selected(self) -> bool:
        """
        Returns True if the technique is selected, False otherwise.
        """
        if self.enabled:
            return self.score is not None or self.color is not None
        return False
    
    def is_deselected(self) -> bool:
        """
        Returns True if the technique is deselected, False otherwise.
        """
        return not self.is_selected()
    
    def __bool__(self):
        return self.is_selected()


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

    @property
    def technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques}

    @property
    def selected_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_selected()}
    
    @property
    def deselected_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_deselected()}

    def replace_color(self, old_color: str, new_color: str):
        found = False
        for technique in self.techniques:
            if technique.color == old_color:
                technique.color = new_color
                found = True

        if not found:
            raise ValueError(f"Color not found: {old_color}")
        
    def __dict__(self):
        data = dataclasses.asdict(self)
        data = util.prune_dict(data)
        return data
    
    def __iter__(self) -> Iterator[Technique]:
        yield from self.techniques


def read_layer(path: str) -> Layer:
    """
    Read the layer from the specified file path.
    """
    path = util.get_real_path(path)
    with open(path, 'r') as fp:
        data = json.load(fp)
        return dacite.from_dict(data_class=Layer, data=data)


# TODO
def write_layer(layer: Layer, path: str) -> Layer:
    """
    Write the provided layer to the specified file path.
    """
    path = util.get_real_path(path)
    if path.endswith('.json'):
        with open(path, 'w') as fp:
            json.dump(layer.__dict__(), fp, cls=JSONEncoder, indent=4)
    else:
        raise ValueError(f"Unsupported file format: {path}")
