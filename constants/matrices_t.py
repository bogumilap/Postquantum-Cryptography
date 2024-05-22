from dataclasses import dataclass
from typing import List


@dataclass
class matrices_t:
    nmatrices: int
    rows: int
    columns: int
    data: List[int]
