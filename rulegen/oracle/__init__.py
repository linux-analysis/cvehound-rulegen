"""The oracle: score a candidate rule by running it.

Built on cvehound.oracle (mini-trees + verdict cache) so a verdict here can
never drift from what the cvehound test suite computes; the suite remains the
final acceptance authority for any rule kept.
"""
