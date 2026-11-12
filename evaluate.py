#!/usr/bin/env python3
"""Phase 6 entry point: python evaluate.py [--dataset data/eval] [--out results]"""
import sys

from ghostap.evaluate import main

if __name__ == "__main__":
    sys.exit(main())
