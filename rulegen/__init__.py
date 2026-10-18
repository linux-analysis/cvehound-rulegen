"""Testbench for models that generate cvehound rules, and the pipeline that runs them.

The bench turns each kernel CVE into (input, oracle) pairs: the input is built
from the fix commit (and history around it) by rulegen.extract/promptbuild, and
the oracle scores a candidate .cocci rule by actually running it against
materialized kernel trees via cvehound.oracle (rulegen.oracle). The unmodified
cvehound test suite remains the final authority: an accepted rule must pass
`pytest --runslow --cve=<CVE>` in the cvehound checkout.
"""
