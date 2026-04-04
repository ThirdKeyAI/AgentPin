"""Reference: AgentPin credential extraction as a FastAPI dependency.

Usage:
    pip install fastapi uvicorn agentpin
    uvicorn examples.fastapi_middleware:app --reload

This is example code — copy and adapt for your own server.
"""

from fastapi import Depends, FastAPI, HTTPException, Request

from agentpin.transport import http_extract_credential

app = FastAPI(title="AgentPin Example Server")


async def get_agentpin_credential(request: Request) -> str:
    """FastAPI dependency that extracts and returns the AgentPin JWT."""
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        jwt = http_extract_credential(auth)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

    # In production, verify the credential here:
    #   from agentpin import verify_credential_offline
    #   result = verify_credential_offline(jwt, discovery_doc, ...)
    #   if not result["valid"]:
    #       raise HTTPException(status_code=403, detail=result["error"])

    return jwt


@app.get("/protected")
async def protected_route(credential: str = Depends(get_agentpin_credential)):
    return {"message": f"Authenticated with credential: {credential[:20]}..."}


@app.get("/health")
async def health():
    return {"status": "ok"}
