"""Learning loop (Phase 7): block -> mined candidate -> human review -> signed
rule bundle -> auto-generated regression test. Unsigned bundles are refused."""

from .bundle import UnsignedBundleError, build_bundle, load_bundle
from .miner import Candidate, mine
from .scanner import LearnedScanner
from .testgen import generate_tests

__all__ = [
    "Candidate",
    "LearnedScanner",
    "UnsignedBundleError",
    "build_bundle",
    "generate_tests",
    "load_bundle",
    "mine",
]
