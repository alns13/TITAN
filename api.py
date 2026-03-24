from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
from pydantic import BaseModel
from typing import Dict, Any
import sys
import os

#add src/ dir to sys.path list
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.append(src_path)
from v2_inference import load_resources, predict_packet

#keep TITAN running until shutdown or toggle off
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("TITAN: Loading into RAM")
    app.state.titan, app.state.scaler, app.state.blueprint = load_resources()
    print("TITAN: Loaded and Ready")
    yield
    print("TITAN: Shutting Down...")

app = FastAPI(title="TITAN IDS API", lifespan=lifespan)

#define and validate packet structure
class packet(BaseModel):
    data: Dict[str, Any]

#call predict_packet function
@app.post("/predict")
async def process_packet(payload: packet):
   features = payload.data
   model = app.state.titan
   scaler = app.state.scaler  
   blueprint = app.state.blueprint  
   return predict_packet(features, model, scaler, blueprint)


