import collections
from dataclasses import dataclass
import dataclasses
from typing import Dict, Iterable, Iterator, List, Optional, Set, Union
import logging

from mitre_attack_navigator_layer_builder.util import JSONEncoder
from mitre_attack_navigator_layer_builder import coloring, util, parsers
from mitre_attack_navigator_layer_builder.parsers import MitreDecoder
from mitre_attack_navigator_layer_builder.coloring import ColorScheme, DiffColorScheme, GradientColorScheme, IntersectionColorScheme, LabeledColorScheme, SingleColorScheme
from mitre_attack_navigator_layer_builder.constants import ALL, ATTACK_NAVIGATOR_LAYER_VERSION, ATTACK_NAVIGATOR_VERSION, AVG, MAX, MITRE_ATTACK_ENTERPRISE, MITRE_ATTACK_ICS, MITRE_ATTACK_MOBILE, NONE, SIDE, SORT_ASCENDING_BY_TECHNIQUE_NAME

logger = logging.getLogger(__name__)


@dataclass()
class Link:
    """
    Links can be embedded in techniques or layers to provide additional context or references.
    """
    label: str
    url: str


@dataclass()
class LegendItem:
    """
    A legend item allows you to associate a colour with a label to make it easier to understand a given layer (e.g., when looking at the intersection or union of two layers).
    """
    label: str
    color: str


@dataclass()
class MetadataItem:
    """
    Metadata items can be embedded in techniques or layers to provide additional context or references.
    """
    name: str
    value: str


@dataclass()
class Divider:
    """
    A divider can be added to separate groups of metadata or links.
    """
    divider: bool = True


@dataclass()
class Gradient:
    """
    A gradient that can be used to assign colours to techniques within the Mitre ATT&CK Navigator web application based on their score.
    
    When exporting layers (e.g., in XLSX, Parquet, JSON, JSONL, or CSV format), we can use the gradient to assign colours to techniques based on their scores.
    """
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
    """
    A technique included in a layer.
    """
    techniqueID: str                # The technique ID (e.g., "T1003")
    tactic: Optional[str] = None    # The tactic shortname (e.g., "initial-access")
    showSubtechniques: bool = False # Sub-techniques can be expanded on a per technique basis (e.g., to allow users to expand and collapse techiques).
    enabled: Optional[bool] = True  # Whether the technique is enabled (i.e., visible in the layer).
    score: Optional[int] = None     # The score assigned to the technique (0 - 100).
    color: Optional[str] = None     # The color assigned to the technique (e.g., "#ff0000").
    comment: Optional[str] = None   # A comment associated with the technique.
    metadata: List[Union[MetadataItem, Divider]] = dataclasses.field(default_factory=list) # Metadata items associated with the technique.
    links: List[Union[Link, Divider]] = dataclasses.field(default_factory=list)            # Links associated with the technique (e.g., links to supporting threat intelligence).

    @property
    def id(self) -> str:
        return self.techniqueID
    
    def is_selected(self) -> bool:
        return self.enabled and any((self.score, self.color))
    
    def is_deselected(self) -> bool:
        return not self.is_selected()
    
    def is_enabled(self) -> bool:
        return self.enabled is True
    
    def is_disabled(self) -> bool:
        return self.enabled is False
    
    def __bool__(self) -> bool:
        return self.is_selected()


@dataclass()
class Versions:
    """
    The ATT&CK, ATT&CK Navigator, and ATT&CK Navigator layer versions used in the layer.
    """
    attack: Optional[str] = None
    navigator: str = ATTACK_NAVIGATOR_VERSION
    layer: str = ATTACK_NAVIGATOR_LAYER_VERSION


@dataclass()
class Filter:
    """
    Filters can be used to limit the techniques displayed in the layer.
    """
    platforms: List[str] = dataclasses.field(default_factory=list)


@dataclass()
class Layout:
    """
    The layout of the layer in the Mitre ATT&CK Navigator web application.
    """
    layout: str = SIDE                  # The layout type (side, flat, mini).
    showID: bool = False                # Whether or not to show the technique ID.
    showName: bool = True               # Whether or not to show the technique name.
    showAggregateScores: bool = False
    countUnscored: bool = False
    aggregateFunction: str = AVG
    expandedSubtechniques: str = ALL  # The subtechniques to expand by default (e.g., "none", "all", "annotated").


@dataclass()
class Layer:
    """
    An ATT&CK Navigator layer.
    """
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
        return self.get_technique_ids()

    @property
    def selected_technique_ids(self) -> Set[str]:
        return self.get_selected_technique_ids()
    
    @property
    def deselected_technique_ids(self) -> Set[str]:
        return self.get_deselected_technique_ids()
    
    def get_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques}
    
    def get_enabled_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_enabled()}
    
    def get_disabled_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_disabled()}
    
    def get_selected_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_selected()}
    
    def get_deselected_technique_ids(self) -> Set[str]:
        return {technique.techniqueID for technique in self.techniques if technique.is_deselected()}

    def select_techniques(
            self, 
            technique_ids: Iterable[str], 
            color: Optional[str], 
            score: Optional[int] = None) -> "Layer":

        technique_ids = set(technique_ids)
        assert technique_ids, "No technique IDs provided"

        existing_technique_ids = self.technique_ids
        new_technique_ids = technique_ids - existing_technique_ids

        color = coloring.get_hex_color_value(color) if color else None

        # Add techniques.
        if new_technique_ids:
            for technique_id in new_technique_ids:
                technique = Technique(
                    techniqueID=technique_id, 
                    score=score, 
                    color=color,
                )
                self.techniques.append(technique)
        
        # Update techniques.
        if existing_technique_ids:
            for i, technique in enumerate(self.techniques):
                if technique.techniqueID in technique_ids:
                    technique.enabled = True
                    technique.score = score
                    technique.color = color
                    self.techniques[i] = technique

        return self

    def deselect_techniques(self, technique_ids: Set[str], score: Optional[int] = None, reset_color: bool = False, disable: bool = False) -> "Layer":
        technique_ids = set(technique_ids)
        assert technique_ids, "No technique IDs provided"
        
        # Deselect any techniques that exist in the layer.
        for i, technique in enumerate(self.techniques):
            if technique.techniqueID in technique_ids:
                if disable:
                    technique.enabled = False

                if score is not None:
                    technique.score = score

                if reset_color:
                    technique.color = None

                self.techniques[i] = technique
            
        # Add any missing techniques.
        missing_technique_ids = technique_ids - self.technique_ids
        for technique_id in missing_technique_ids:
            technique = Technique(
                techniqueID=technique_id,
                enabled=False,
                score=score,
            )
            self.techniques.append(technique)
        
        return self
    
    def disable_deselected_techniques(self) -> "Layer":
        for i, technique in enumerate(self.techniques):
            if technique.is_deselected():
                self.techniques[i].enabled = False
        return self
    
    def set_subtechnique_visibility(self, visible: bool) -> "Layer":
        for i, _ in enumerate(self.techniques):
            self.techniques[i].showSubtechniques = visible
        return self

    def get_colors(self, include_color_gradient: bool = False) -> List[str]:
        colors = {technique.color for technique in self.techniques if technique.color}
        if include_color_gradient and self.gradient:
            colors |= set(self.gradient.colors)
        return sorted(colors)

    def drop_comments(self) -> "Layer":
        for i, _ in enumerate(self.techniques):
            self.techniques[i].comment = None
        return self

    def drop_legend_items(self) -> "Layer":
        self.legendItems = []
        return self
    
    def drop_tactic_mappings(self) -> "Layer":
        for i, _ in enumerate(self.techniques):
            self.techniques[i].tactic = None
        return self
    
    def get_scores(self) -> Dict[str, int]:
        scores = {}
        for technique in self.techniques:
            if technique.is_selected() and technique.score is not None:
                scores[technique.techniqueID] = technique.score
        return scores

    def reset_scores(self, score: Optional[int] = None) -> "Layer":
        for i, _ in enumerate(self.techniques):
            self.techniques[i].score = score
        return self
    
    def __dict__(self):
        data = dataclasses.asdict(self)
        return data
    
    def __iter__(self) -> Iterator[Technique]:
        yield from self.techniques


def merge_layers_as_heatmap(layers: List[Layer]) -> Layer:
    domains = {layer.domain for layer in layers}
    assert len(domains) == 1, f'All layers must have the same domain - got {domains}'
    
    technique_scores = collections.defaultdict(int)
    for layer in layers:
        for technique in layer.techniques:
            if technique.enabled:
                technique_scores[technique.id] += 1
    
    max_score = max(technique_scores.values())
    color_scheme = GradientColorScheme()
    color_map = color_scheme.get_color_map(max_score)

    layer = Layer(
        domain=next(iter(domains)),
        gradient=Gradient(
            minValue=1,
            maxValue=max_score,
            colors=list(color_map.values()),
        )
    )
    for technique, score in technique_scores.items():
        technique = Technique(
            techniqueID=technique, 
            score=score, 
            color=color_map[score],
        )
        layer.techniques.append(technique)
    
    return layer


# TODO
def apply_color_scheme(layer: Layer, color_scheme: Union[str, ColorScheme]) -> Layer:
    if isinstance(color_scheme, str):
        return apply_single_color_scheme(layer, SingleColorScheme(color_scheme))
    elif isinstance(color_scheme, SingleColorScheme):
        return apply_single_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, GradientColorScheme):
        return apply_gradient_color_scheme(layer, color_scheme)
    elif isinstance(color_scheme, LabeledColorScheme):
        return apply_labeled_color_scheme(layer, color_scheme)
    else:
        raise ValueError(f'Invalid color scheme: {color_scheme}')


# TODO
def apply_single_color_scheme(layer: Layer, color_scheme: SingleColorScheme) -> Layer:
    techniques = layer.techniques
    for i, technique in enumerate(techniques):
        if technique.enabled:
            technique.color = color_scheme.color
            techniques[i] = technique
    return layer


# TODO
def apply_gradient_color_scheme(layer: Layer, color_scheme: GradientColorScheme) -> Layer:
    techniques = layer.techniques
    scores = {technique.score for technique in techniques}
    
    min_score = min(scores)
    max_score = max(scores)
    color_map = color_scheme.get_color_map(max_score)
    
    for i, technique in enumerate(techniques, start=min_score):
        techniques[i].color = color_map[technique.score]
    return layer


# TODO
def apply_labeled_color_scheme(layer: Layer, color_scheme: LabeledColorScheme) -> Layer:
    techniques = layer.techniques
    for i, technique in enumerate(techniques):
        if technique.enabled:
            technique.color = color_scheme.colors_to_labels.get(technique.id)
            techniques[i] = technique
    return layer


UNION = 'union'
INTERSECTION = 'intersection'
LEFT_DIFF = 'left_diff'
RIGHT_DIFF = 'right_diff'
SYMMETRIC_DIFF = 'symmetric_diff'

MERGE_STRATEGIES = [
    UNION,
    INTERSECTION,
    LEFT_DIFF,
    RIGHT_DIFF,
    SYMMETRIC_DIFF,
]

DEFAULT_MERGE_STRATEGY = UNION


# TODO
def merge(a: Layer, b: Layer, merge_strategy: str) -> Layer:
    f = MERGE_STRATEGIES_TO_FUNCTIONS[merge_strategy]    
    c = f(a, b)
    return c


def get_selected_technique_ids(layer: Layer) -> Set[str]:
    return {technique.id for technique in layer.techniques if technique.is_selected()}


def get_deselected_techniques(layer: Layer) -> Set[str]:
    return {technique.id for technique in layer.techniques if technique.is_deselected()}


# TODO
def calculate_heatmap(layers: List[Layer], color_scheme: Optional[GradientColorScheme] = None) -> Layer:
    techniques = []
    color_scheme = color_scheme or GradientColorScheme()

    # Rank techniques by frequency.
    m = collections.defaultdict(int)
    for layer in layers:
        for technique_id in layer.get_selected_technique_ids():
            m[technique_id] += 1
        
    max_score = max(m.values())
    color_map = color_scheme.get_color_map(max_score)

    for technique, score in m.items():
        technique = Technique(
            techniqueID=technique, 
            score=score, 
            color=color_map[score],
        )
        techniques.append(technique)

    # Add any other techniques.
    all_technique_ids = {technique.id for layer in layers for technique in layer.techniques}
    for technique_id in all_technique_ids:
        if technique_id not in m:
            technique = Technique(
                techniqueID=technique_id,
            )
            techniques.append(technique)

    layer = Layer(
        name='Heatmap',
        gradient=Gradient(
            minValue=1,
            maxValue=max_score,
            colors=list(color_map.values()),
        ),
        techniques=techniques,
    )
    return layer


# TODO
def calculate_diff(a: Layer, b: Layer) -> Layer:
    return calculate_left_diff(a, b)


# TODO: here
def calculate_left_diff(a: Layer, b: Layer, color_scheme: Optional[DiffColorScheme] = None) -> Layer:
    raise NotImplementedError()


# TODO
def calculate_right_diff(a: Layer, b: Layer) -> Layer:
    return calculate_left_diff(b, a)


# TODO
def calculate_symmetric_diff(a: Layer, b: Layer) -> Layer:
    raise NotImplementedError()


def calculate_union(a: Layer, b: Layer, color_scheme: Optional[SingleColorScheme]) -> Layer:
    color_scheme = color_scheme or SingleColorScheme()

    layer = Layer(
        name=f'{a.name} ∪ {b.name}',
        description=f'Union of {a.name} and {b.name}',
    )

    selected_techniques = a.get_selected_technique_ids() | b.get_selected_technique_ids()
    all_techniques = a.technique_ids | b.technique_ids
    for technique_id in all_techniques:
        enabled = technique_id in selected_techniques
        technique = Technique(
            techniqueID=technique_id,
            enabled=enabled,
            color=color_scheme.color,
        )
        layer.techniques.append(technique)

    return layer


def calculate_intersection(a: Layer, b: Layer, color_scheme: Optional[IntersectionColorScheme] = None) -> Layer:
    color_scheme = color_scheme or IntersectionColorScheme()
    legend = [
        LegendItem(label=a.name, color=coloring.get_hex_color_value(color_scheme.left_color)),
        LegendItem(label='Intersection', color=coloring.get_hex_color_value(color_scheme.intersection_color)),
        LegendItem(label=b.name, color=coloring.get_hex_color_value(color_scheme.right_color)),
    ]
    layer = Layer(
        name=f'{a.name} ∩ {b.name}',
        description=f'Intersection of {a.name} and {b.name}',
        legendItems=legend,
    )

    # Calculate the intersection.
    l = a.get_selected_technique_ids()
    r = b.get_selected_technique_ids()
    i = l & r

    # Add the techniques to the layer.
    for technique_id in a.technique_ids | b.technique_ids:
        enabled = True
        if technique_id in i:
            color = color_scheme.intersection_color
        elif technique_id in l:
            color = color_scheme.left_color
        elif technique_id in r:
            color = color_scheme.right_color
        else:
            color = None
            enabled = False

        technique = Technique(
            techniqueID=technique_id,
            color=color,
            enabled=enabled,
        )
        layer.techniques.append(technique)

    return layer


MERGE_STRATEGIES_TO_FUNCTIONS = {
    UNION: calculate_union,
    INTERSECTION: calculate_intersection,
    LEFT_DIFF: calculate_left_diff,
    RIGHT_DIFF: calculate_right_diff,
    SYMMETRIC_DIFF: calculate_symmetric_diff,
}


# TODO
def enrich_layer(layer: Layer, stix2_objects: Iterable[dict]) -> Layer:
    raise NotImplementedError()


# TODO
def add_missing_techniques(layer: Layer, stix2_objects: Iterable[dict], enable: bool = True) -> Layer:
    decoder = MitreDecoder()

    all_technique_ids = {decoder.get_external_id(o) for o in stix2_objects if o['type'] == 'attack-pattern'}
    existing_technique_ids = layer.technique_ids
    missing_technique_ids = all_technique_ids - existing_technique_ids

    logger.info("Adding %d missing techniques to layer: `%s` (enabled: %s)", len(missing_technique_ids), layer.name, enable)
    for technique_id in missing_technique_ids:
        technique = Technique(
            techniqueID=technique_id,
            enabled=enable,
        )
        layer.techniques.append(technique)
    
    return layer


# TODO
def add_missing_tactic_shortnames(layer: Layer, tactics: Iterable[dict], techniques: Iterable[dict]) -> Layer:
    pass
