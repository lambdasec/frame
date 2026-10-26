from fastapi import Depends, FastAPI, Request
from repo import Repo, get_repo

app = FastAPI()


@app.get('/u')
async def u(request: Request, repo: Repo = Depends(get_repo)):
    return repo.find('admin')
