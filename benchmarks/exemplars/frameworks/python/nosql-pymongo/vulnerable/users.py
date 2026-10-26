from pymongo import MongoClient

client = MongoClient("mongodb://localhost")
db = client.appdb


def authenticate(username, password):
    return db.users.find_one({"username": username, "password": password})  # frame-expect: CWE-943


def search_by_name(name):
    query = {"$where": "this.name == '" + name + "'"}
    return list(db.users.find(query))  # frame-expect: CWE-943


def filter_users(criteria):
    return list(db.users.find(criteria))  # frame-expect: CWE-943


def stats_for(group):
    pipeline = [{"$group": {"_id": "$" + group, "n": {"$sum": 1}}}]
    return list(db.users.aggregate(pipeline))  # frame-expect: CWE-943
