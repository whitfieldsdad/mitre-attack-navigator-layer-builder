import click
import logging


@click.group()
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")   


if __name__ == "__main__":
    main()
