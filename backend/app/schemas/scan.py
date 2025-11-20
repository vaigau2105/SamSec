from pydantic import BaseModel
from typing import List, Optional, Any

class ScanCreate(BaseModel):
    name: str
    targets: List[str]

class ScanOut(BaseModel):
    id: int
    name: str
    targets: List[str]
    status: str
    raw_results: Optional[Any] = None
    result_summary: Optional[Any] = None

    class Config:
        from_attributes = True
