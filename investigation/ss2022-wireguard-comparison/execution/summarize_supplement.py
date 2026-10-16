#!/usr/bin/env python3
"""Reuse original exact arithmetic, with only supplement corpus cardinalities changed."""
from pathlib import Path
source=(Path(__file__).resolve().parent.parent/'summarize_cohort.py').read_text()
source=source.replace('len(files)!=140','len(files)!=28').replace('exactly140','exactly28').replace('len(records)!=20','len(records)!=4').replace('all20','all4').replace("'cells':140","'cells':28")
exec(compile(source,'original-summarize_cohort-with-supplement-cardinalities.py','exec'))
