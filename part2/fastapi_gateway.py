from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Smart Guard REST API", version="1.0", description="Swagger UI Gateway for C Backend")

C_SERVER = "https://127.0.0.1:8443"

class CommandPayload(BaseModel):
    cmd: str

@app.get("/API/V1/TELEMETRY", tags=["Monitoring"])
def get_telemetry():
    response = requests.get(f"{C_SERVER}/API/V1/TELEMETRY", verify=False)
    return response.json()

@app.get("/API/V1/PERSONS", tags=["Monitoring"])
def get_persons():
    response = requests.get(f"{C_SERVER}/API/V1/PERSONS", verify=False)
    return response.json()

@app.get("/API/V1/HISTORY", tags=["Monitoring"])
def get_history():
    response = requests.get(f"{C_SERVER}/API/V1/HISTORY", verify=False)
    return response.json()

@app.post("/API/V1/COMMAND", tags=["Control"])
def send_command(payload: CommandPayload):
    url_with_command = f"{C_SERVER}/API/V1/COMMAND?action={payload.cmd}"
   
    response = requests.post(url_with_command, verify=False)
    
    try:
        return response.json()
    except:
        return {"status": "Command sent to C server"}

@app.get(
    "/API/V1/STREAM", 
    tags=["Video"],
    summary="Live Video Stream",
    description='''
    <h3>Live Stream Player</h3>
    <p>The video below is fetched live from the C server and rendered directly within the Swagger UI:</p>
    <div style="text-align: center; margin: 15px 0;">
        <img src="/API/V1/STREAM" style="width: 100%; max-width: 500px; border: 4px solid #28a745; border-radius: 12px; box-shadow: 0px 4px 10px rgba(0,0,0,0.3);">
    </div>
    '''
)
def get_stream():
    def iterfile():
        with requests.get(f"{C_SERVER}/API/V1/STREAM", verify=False, stream=True) as r:
            for chunk in r.iter_content(chunk_size=1024):
                yield chunk
    return StreamingResponse(iterfile(), media_type="multipart/x-mixed-replace; boundary=frame")
