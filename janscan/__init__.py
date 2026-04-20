"""JanScan — Linux Security Audit Tool"""

import os

__version__ = "1.0.0"
IS_ROOT = os.getuid() == 0
