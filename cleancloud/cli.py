import click

from cleancloud.doctor.command import doctor
from cleancloud.scan.command import scan


@click.group()
def cli():
    """CleanCloud – Safe cloud hygiene scanner"""
    pass


cli.add_command(doctor)
cli.add_command(scan)


def main():
    cli()


if __name__ == "__main__":
    main()
