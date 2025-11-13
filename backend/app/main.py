from fastapi import FastAPI
from app.api.endpoints import scan  # Import our new router

# Create the main app instance
app = FastAPI(title="Samsec API")

# "Include" the router.
# This makes our /scan-target endpoint available.
app.include_router(scan.router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"message": "Welcome to the Samsec API. Go to /docs for API info."}