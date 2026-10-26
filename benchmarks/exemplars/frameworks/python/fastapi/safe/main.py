import html
import os
import re
import subprocess
from typing import Optional

from fastapi import Body, Depends, FastAPI, File, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from pydantic import BaseModel

from db import get_session
from repository import ProductRepository

app = FastAPI()


class Search(BaseModel):
    name: str
    category: Optional[str] = None


@app.get("/products")
def list_products(q: str = Query(...), session=Depends(get_session)):
    return ProductRepository(session).search(q)


@app.post("/products/search")
def search_products(payload: Search, session=Depends(get_session)):
    return ProductRepository(session).by_category(payload.category)


@app.get("/products/{sku}")
async def product(sku: str, session=Depends(get_session)):
    return ProductRepository(session).by_sku(sku)


@app.get("/welcome", response_class=HTMLResponse)
def welcome(name: str = Query("guest")):
    return HTMLResponse("<h1>Welcome " + html.escape(name) + "</h1>")


@app.get("/out")
def out(to: str):
    return RedirectResponse(url="/products")


@app.get("/export")
def export(name: str):
    return FileResponse(os.path.join("/srv/exports", os.path.basename(name)))


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    dest = os.path.join("/srv/uploads", os.path.basename(file.filename))
    with open(dest, "wb") as fh:
        fh.write(await file.read())
    return {"ok": True}


@app.post("/ping")
async def ping(request: Request):
    data = await request.json()
    subprocess.run(["ping", "-c", "1", data["host"]])
    return {"ok": True}


@app.post("/convert")
def convert(fmt: str = Body(..., embed=True)):
    subprocess.run(["convert", "in.png", "out." + fmt])
    return {"ok": True}
