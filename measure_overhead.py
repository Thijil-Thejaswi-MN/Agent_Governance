#!/usr/bin/env python3
import sys
from pathlib import Path

# Delegate to demo/security_monitor/measure_overhead.py
sys.path.insert(0, str(Path(__file__).resolve().parent / "demo" / "security_monitor"))
from measure_overhead import main

if __name__ == "__main__":
    sys.exit(main())
