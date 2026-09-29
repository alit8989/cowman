"""Application entrypoint for the COWMAN executable."""

import sys
from cowman.cli.app import app


def main():
    """Main CLI runner."""
    app()


if __name__ == "__main__":
    main()
