from pydantic import BaseModel


class UploadResponse(BaseModel):
    id: int
    filename: str
    stored_filename: str
    url: str
    uploaded: int = 1
    resource_url: str | None = None
