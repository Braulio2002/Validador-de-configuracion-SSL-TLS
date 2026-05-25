from app.presentation.cli import Cli


def main() -> None:
    """Punto de entrada de la aplicación."""
    cli = Cli()
    cli.run()


if __name__ == "__main__":
    main()
