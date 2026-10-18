"""Decoy trees: unrelated kernel code served at the candidate rule's own paths.

check_cve() scans only the rule's Files: paths, so a decoy that merely holds
other CVEs' files would never be read. Instead each decoy places one large,
unrelated source file's blob AT the candidate's first Files: path — the rule's
pattern runs against foreign code, and a rule generic enough to fire there is
degenerate. Signatures are synthetic but well-formed, so verdicts share the
regular result cache.
"""

from cvehound.oracle.kerneltree import BlobMaterializer, Sig, object_header

# Large, structurally diverse files, pinned at one tag so decoy content is
# stable across kernel fetches. A candidate whose Files: overlap a decoy's
# source path skips that decoy (it could legitimately match).
DECOY_TAG = 'v6.6'
DECOY_SOURCES = (
    'kernel/sched/core.c',
    'fs/ext4/inode.c',
    'net/core/dev.c',
    'drivers/usb/core/hcd.c',
    'mm/slub.c',
    'lib/vsprintf.c',
    'crypto/algapi.c',
    'block/bio.c',
)


def decoy_blobs(materializer: BlobMaterializer) -> list[tuple[str, str]]:
    """[(source_path, blob_oid)] for the decoy corpus; missing paths skipped."""
    blobs = []
    for path in DECOY_SOURCES:
        obj = object_header(materializer.git, f'{DECOY_TAG}:{path}')
        if obj is not None and obj[1] == 'blob':
            blobs.append((path, obj[0]))
    return blobs


def decoy_sigs(blobs: list[tuple[str, str]], rule_files: list[str]) -> list[tuple[str, Sig]]:
    """One synthetic signature per decoy: the decoy blob at the rule's path."""
    if not rule_files:
        return []
    anchor = next((path for path in rule_files if path.endswith('.c')), rule_files[0])
    sigs = []
    for source, oid in blobs:
        if source in rule_files:
            continue
        sigs.append((source, ((anchor, oid),)))
    return sigs
