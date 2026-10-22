"""pytest configuration – adds the project root to sys.path."""
import sys
import pathlib

# Allow imports like `from secrettriage.detectors...` from any working directory
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
