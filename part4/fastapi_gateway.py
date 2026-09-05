from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import requests
import urllib3

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
    data = {"cmd": payload.cmd}
    response = requests.post(f"{C_SERVER}/API/V1/COMMAND", json=data, verify=False)
    return response.json()

@app.get("/API/V1/STREAM", tags=["Video"])
def get_stream():
    def iterfile():
        with requests.get(f"{C_SERVER}/API/V1/STREAM", verify=False, stream=True) as r:
            for chunk in r.iter_content(chunk_size=1024):
                yield chunk
    return StreamingResponse(iterfile(), media_type="multipart/x-mixed-replace; boundary=frame")
