"""PyInstaller entry point. Imports the package by absolute name so relative
imports inside the package keep working when frozen into a single binary."""
from domain_monitor.cli import main

if __name__ == "__main__":
    main()
