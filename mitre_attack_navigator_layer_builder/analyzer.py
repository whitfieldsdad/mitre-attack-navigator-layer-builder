from mitre_attack_navigator_layer_builder.types.layer import Layer
from mitre_attack_navigator_layer_builder.types.layer_summary import LayerSummary


def get_layer_summary(layer: Layer) -> LayerSummary:
    """
    Summarizes a layer.
    """
    unique_colors = set()
    unique_color_names = set()
    unique_scores = set()
    selected_techniques = set()
    hidden_techniques = set()

    for technique in layer.techniques:
        if technique.hidden:
            hidden_techniques.add(technique.technique_id)
        else:
            selected_techniques.add(technique.technique_id)

        color = technique.color
        if color:
            unique_colors.add(color)
            color_name = technique.color_name
            if color_name:
                unique_color_names.add(color_name)

        if technique.score is not None:
            unique_scores.add(technique.score)

    return LayerSummary(
        name=layer.name,
        description=layer.description,
        domain=layer.domain,
        versions=layer.versions,
        hidden_techniques=sorted(hidden_techniques),
        selected_techniques=sorted(selected_techniques),
        unique_colors=sorted(unique_colors),
        unique_color_names=sorted(unique_color_names),
        unique_scores=sorted(unique_scores),
    )
