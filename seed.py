"""Root launcher for database & data seeding.

Usage:
    python seed.py
"""
from scripts.seed import aadhaar, run, sample_files

if __name__ == "__main__":
    run()
