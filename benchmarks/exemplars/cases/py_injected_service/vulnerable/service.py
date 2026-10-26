from flask import Flask, request
app = Flask(__name__)
from repo import UserRepo


class UserService:
    def __init__(self, repo: UserRepo):
        self.repo = repo

    def lookup(self):
        return self.repo.find(request.args.get("name"))
