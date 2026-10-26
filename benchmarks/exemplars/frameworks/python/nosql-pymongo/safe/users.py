from pymongo import MongoClient

client = MongoClient("mongodb://localhost")
db = client.appdb


ALLOWED_GROUPS = {"role", "country"}


def hash_password(p):
    import hashlib
    return hashlib.sha256(p.encode()).hexdigest()


def authenticate(username, password):
    return db.users.find_one({"username": str(username), "password_hash": hash_password(str(password))})


def search_by_name(name):
    query = {"name": str(name)}
    return list(db.users.find(query))


def filter_users(criteria):
    return list(db.users.find({"role": str(criteria.get("role", ""))}))


def stats_for(group):
    if group not in ALLOWED_GROUPS:
        raise ValueError(group)
    pipeline = [{"$group": {"_id": "$" + group, "n": {"$sum": 1}}}]
    return list(db.users.aggregate(pipeline))
