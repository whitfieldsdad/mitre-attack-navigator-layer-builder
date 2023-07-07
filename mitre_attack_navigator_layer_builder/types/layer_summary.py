from typing import List, Optional
from mitre_attack_navigator_layer_builder.types.layer import Versions
from pydantic import BaseModel


class LayerSummary(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    domain: Optional[str] = None
    versions: Optional[Versions] = None
    hidden_techniques: List[str] = []
    selected_techniques: List[str] = []
    unique_colors: List[str] = []
    unique_color_names: List[str] = []
    unique_scores: List[int] = []

    @property
    def total_selected_techniques(self) -> int:
        return len(self.selected_techniques)

    @property
    def total_hidden_techniques(self) -> int:
        return len(self.hidden_techniques)

    @property
    def total_unique_colors(self) -> int:
        return len(self.unique_colors)

    @property
    def total_unique_scores(self) -> int:
        return len(self.unique_scores)
