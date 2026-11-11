from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel


class Page(BaseModel):
    limit: int
    offset: int


def _page(
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page:
    return Page(limit=limit, offset=offset)


PageDep = Annotated[Page, Depends(_page)]
