"""The authenticated caller is a value (TaintKind.IDENTITY), never a name in source text: Flask-Login's
`current_user`, a verified JWT's identity, Django's `request.user` (packs: `[[identity]] proxies`,
`[[source]] kind = "identity"`, `[[request_type]] identities`). It is not attacker data at any sink;
it scopes a resource selection to the caller's own objects, and comparing an object's owner with it
is an ownership check. Neither depends on what the variables are called."""

import pytest

from frame.sil.scanner import FrameScanner


def _idor(code, name="a.py"):
    return sorted(v.line for v in FrameScanner(language="python", verify=False).scan(code, name).vulnerabilities
                  if v.cwe_id == "CWE-639")


FLASK = """from flask import Flask, request, abort
from flask_login import current_user
from models import Order
app = Flask(__name__)

@app.route('/o')
def o():
    {body}
"""


@pytest.mark.parametrize("body, idor", [
    ("return str(Order.query.get(request.args['id']))", True),
    # scoped by the caller: the selection is the caller's own order
    ("return str(Order.query.filter_by(owner_id=current_user.id, id=request.args['id']).first())", False),
    ("me = current_user\n    return str(Order.query.filter_by(owner=me, id=request.args['id']).first())", False),
    # an ownership check after the selection
    ("order = Order.query.get(request.args['id'])\n    if order.owner_id != current_user.id:\n        abort(403)\n"
     "    return str(order)", False),
    # a check against something other than the caller proves nothing
    ("order = Order.query.get(request.args['id'])\n    if order.owner_id != request.args['owner']:\n"
     "        abort(403)\n    return str(order)", True),
])
def test_flask_login_scoping(body, idor):
    assert bool(_idor(FLASK.format(body=body))) == idor


def test_a_variable_named_current_user_is_not_the_caller():
    code = FLASK.replace("from flask_login import current_user\n", "").format(
        body="current_user = request.args['who']\n"
             "    return str(Order.query.filter_by(owner_id=current_user, id=request.args['id']).first())")
    assert _idor(code)


def test_a_verified_jwt_identity_scopes_the_selection():
    code = ("from flask import Flask, request\nfrom flask_jwt_extended import get_jwt_identity, jwt_required\n"
            "from models import Order\napp = Flask(__name__)\n\n@app.route('/o')\n@jwt_required()\ndef o():\n"
            "    uid = get_jwt_identity()\n"
            "    return str(Order.query.filter_by(user_id=uid, id=request.args['id']).first())\n")
    assert _idor(code) == []
    assert _idor(code.replace("user_id=uid, ", ""))


DJANGO = """from django.urls import path
from shop.models import Order

def view(request, pk):
    return str({select})

urlpatterns = [path("o/<pk>/", view)]
"""


def test_django_request_user_is_the_caller():
    assert _idor(DJANGO.format(select="Order.objects.get(pk=pk)"), "views.py")
    assert _idor(DJANGO.format(select="Order.objects.get(pk=pk, owner=request.user)"), "views.py") == []


def test_the_caller_is_not_attacker_data():
    code = ("import os\nfrom django.http import HttpResponse\nfrom django.urls import path\n\n"
            "def view(request):\n    os.system('echo ' + request.user.username)\n"
            "    return HttpResponse('Hi ' + request.user.username)\n\nurlpatterns = [path('v/', view)]\n")
    assert FrameScanner(language="python", verify=False).scan(code, "views.py").vulnerabilities == []


DECORATED = """from functools import wraps
from flask import Blueprint, request
import jwt
from models import User, Txn
bp = Blueprint("t", __name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers["Authorization"].split(" ")[1]
        claims = jwt.decode(token, "key", algorithms=["HS256"])
        user = User.query.get(claims["user_id"])
        return f(user, *args, **kwargs)
    return decorated

@bp.route("/t/<int:tid>")
@token_required
def show(me, tid):
    txn = Txn.query.get(tid)
    {check}
    return str(txn)
"""


def test_a_decorator_hands_the_view_the_caller():
    # the wrapper's `f(user, ...)` reaches every function `@token_required` wraps; `user` is the
    # record the verified token's identity selects, so comparing the owner with it is a check
    guarded = DECORATED.format(check="if txn.owner_id != me.id:\n        return 'no', 403")
    assert _idor(guarded) == []
    assert _idor(DECORATED.format(check="pass")) == [19]


def test_the_decorator_can_live_in_another_file(tmp_path):
    head, view = DECORATED.split('bp = Blueprint("t", __name__)\n')
    (tmp_path / "auth.py").write_text(head + view.split("@bp.route")[0])
    (tmp_path / "views.py").write_text("from flask import Blueprint\nfrom auth import token_required\n"
                                       "from models import Txn\nbp = Blueprint('t', __name__)\n\n@bp.route"
                                       + view.split("@bp.route")[1].format(
                                           check="if txn.owner_id != me.id:\n        return 'no', 403"))
    results = FrameScanner(verify=False).scan_directory(str(tmp_path), None)
    assert not [v for r in results for v in r.vulnerabilities if v.cwe_id == "CWE-639"]
