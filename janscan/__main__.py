"""JanScan entrypoint."""

from janscan.config.loader import init_directories
from janscan.storage.db import init_db
from janscan.console.prompt import ConsolePrompt


def main():
    init_directories()
    init_db()
    console = ConsolePrompt()
    console.start()


if __name__ == "__main__":
    main()
