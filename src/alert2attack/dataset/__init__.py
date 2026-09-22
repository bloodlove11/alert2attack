"""Dataset build: OTRF download/normalize into boxed scenarios."""

from alert2attack.dataset.build import build_scenario_from_records, write_scenario_dir
from alert2attack.dataset.catalog import CatalogEntry, load_catalog
from alert2attack.dataset.otrf import iter_normalized, normalize_record
from alert2attack.dataset.window import assign_evidence_ids, box_events

__all__ = [
    "CatalogEntry",
    "assign_evidence_ids",
    "box_events",
    "build_scenario_from_records",
    "iter_normalized",
    "load_catalog",
    "normalize_record",
    "write_scenario_dir",
]
