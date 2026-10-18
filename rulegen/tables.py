"""One convention for every table this bench writes.

Data tables are parquet (same compression, same "make the parent directory"
rule); report tables are a `Table` rendered as markdown and written as CSV;
CVE id lists are text, one id per line under `#` comments. Every writer makes
the parent directory first.
"""

import hashlib
import json
import math
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

COMPRESSION = 'zstd'
# Longest CSV file stem; a longer title keeps its first part and a digest of the
# whole, so two tables whose titles differ only at the end never share a file.
SLUG_MAX = 80


def _parent(path: str) -> str:
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    return path


def write_text(path: str, text: str) -> str:
    with open(_parent(path), 'w') as fh:
        fh.write(text)
    return path


def write_json(path: str, data: Any, indent: int = 1) -> str:
    return write_text(path, json.dumps(data, indent=indent))


def read_ids(path: str) -> set[str]:
    """CVE ids from an id-list file: one per line, '#' comments and blanks skipped."""
    with open(path) as fh:
        return {line.split()[0] for line in fh if line.strip() and not line.startswith('#')}


def write_ids(path: str, ids: Sequence[str], header: Sequence[str] = ()) -> str:
    """An id list `read_ids` reads back: each header line as a `#` comment, then the ids."""
    return write_text(
        path, ''.join(f'# {line}\n' for line in header) + ''.join(f'{i}\n' for i in ids)
    )


def quantile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank quantile: the smallest value with at least a `q` share of `values`
    at or below it (q=0.5 is the lower median, q=1 the maximum); None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    # Rounded first: 0.9 * 10 is 9.000000000000002, whose ceiling is not 9.
    return ordered[max(0, math.ceil(round(q * len(ordered), 9)) - 1)]


def write_rows(rows: Sequence[dict[str, Any]], path: str) -> str:
    import pyarrow as pa
    import pyarrow.parquet as pq

    pq.write_table(pa.Table.from_pylist(list(rows)), _parent(path), compression=COMPRESSION)
    return path


# The command that writes each table under data/, named when a table is read
# before it was built.
BUILT_BY = {
    'cvemeta.parquet': 'rulegen build-cvemeta',
    'cves.parquet': 'rulegen build-corpus',
    'shapes.parquet': 'rulegen shape-corpus',
    'tiers.parquet': 'rulegen tier-corpus',
}


def missing_table(path: str) -> str:
    """Why `path` cannot be read, and what builds it."""
    command = BUILT_BY.get(os.path.basename(path))
    if command is None and os.path.basename(os.path.dirname(path)) == 'examples':
        command = 'rulegen build-dataset'
    if command is None:
        return f'{path} does not exist'
    return (
        f'{path} does not exist; build it with `{command}` (README.md, Data), or run '
        '`scripts/bootstrap.sh setup`, which builds the data tables in order'
    )


def read_rows(path: str) -> list[dict[str, Any]]:
    import pyarrow.parquet as pq

    if not os.path.exists(path):
        raise FileNotFoundError(missing_table(path))
    return pq.read_table(path).to_pylist()


@dataclass
class Table:
    title: str
    columns: list[str]
    rows: list[list[Any]] = field(default_factory=list)
    note: str = ''


def render_markdown(tables: Sequence[Table]) -> str:
    out: list[str] = []
    for table in tables:
        out.append(f'### {table.title}\n')
        out.append('| ' + ' | '.join(table.columns) + ' |')
        out.append('|' + '---|' * len(table.columns))
        for row in table.rows:
            out.append('| ' + ' | '.join('' if v is None else str(v) for v in row) + ' |')
        if table.note:
            out.append(f'\n_{table.note}_')
        out.append('')
    return '\n'.join(out)


def slug(title: str) -> str:
    """The CSV file stem for a table title, unique to that title."""
    name = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')
    if len(name) > SLUG_MAX:
        digest = hashlib.sha256(name.encode()).hexdigest()[:7]
        name = f'{name[: SLUG_MAX - 8].rstrip("-")}-{digest}'
    return name


def write_csv(tables: Sequence[Table], out_dir: str) -> list[str]:
    import csv

    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for table in tables:
        path = os.path.join(out_dir, f'{slug(table.title)}.csv')
        with open(path, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(table.columns)
            writer.writerows(table.rows)
        paths.append(path)
    return paths
