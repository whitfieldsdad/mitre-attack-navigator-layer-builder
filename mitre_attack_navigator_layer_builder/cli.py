import mitre_attack_navigator_layer_builder.loader as loader
import mitre_attack_navigator_layer_builder.analyzer as analyzer
import click
import logging


@click.group()
def cli():
    pass


@cli.command()
@click.argument("input-file", required=True)
def summarize_layer(input_file: str):
    """
    Summarize a layer
    """
    layer = loader.read_layer(input_file)
    summary = analyzer.get_layer_summary(layer)
    blob = loader.to_json(summary)
    print(blob)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def disable_selected_techniques(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.disable_selected_techniques()
    loader.save_layer(layer, output_file)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def disable_deselected_techniques(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.disable_deselected_techniques()
    loader.save_layer(layer, output_file)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def expand_subtechniques(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.expand_subtechniques()
    loader.save_layer(layer, output_file)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def collapse_subtechniques(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.collapse_subtechniques()
    loader.save_layer(layer, output_file)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def remove_descriptions(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.remove_descriptions()
    loader.save_layer(layer, output_file)


@cli.command()
@click.argument("input-file", required=True)
@click.argument("output-file", required=True)
def remove_colors(input_file: str, output_file: str):
    layer = loader.read_layer(input_file)
    layer.remove_colors()
    loader.save_layer(layer, output_file)


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    cli()


if __name__ == "__main__":
    main()
