#!/usr/bin/env python3

from typing import Optional

from fastapi import FastAPI, Header
from fxaclient import FxaClient

app = FastAPI()


@app.get("/")
async def root():
    return {
        "/logins": "Retrieve logins",
        "/bookmarks": "Retrieve bookmarks"
    }


@app.get("/logins")
async def logins(x_user: Optional[str] = Header(None), x_password: Optional[str] = Header(None)):
    fxa = FxaClient(x_user, x_password, 'passwords')

    return fxa.retrieve_records()


@app.get("/bookmarks")
async def bookmarks(x_user: Optional[str] = Header(None), x_password: Optional[str] = Header(None)):
    fxa = FxaClient(x_user, x_password, 'bookmarks')

    return fxa.retrieve_records()
