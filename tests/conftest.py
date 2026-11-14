import sys
from pathlib import Path

# Make `import backend...` work no matter where pytest is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
