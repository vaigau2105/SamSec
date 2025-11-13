from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    # We are setting rules: must be at least 3 chars, max 255.
    target: str = Field(min_length=3, max_length=255)

class ScanResponse(BaseModel):

    status: str
    message: str
    scan_id: str | None = None 