"""Authorization grant-soundness (CWE-863), translator `_authorization_soundness_checks`.

An authorization-decision function is UNSOUND when it grants access on a path that binds the
resource to the caller AND on another path that does not: the access predicate is under-constrained,
so a caller is granted access to a resource that is not theirs. This is the real open-webui
`has_access_to_file` bug (GHSA-26g9-27vm-x3q8): it returns True when the caller owns the file, but
ALSO returns True when a shared chat references it, never checking the caller can access that chat.

The check is path-sensitive (every GRANT path is examined on its own) and conservative: it fires
only on an INTERNAL inconsistency -- the same function both scopes and does not scope a grant --
never on a function that simply never scopes (which may be a legitimately public check).
"""

from frame.sil.scanner import FrameScanner

HEAD = ("from flask import Flask, abort, jsonify\n"
        "from flask_login import login_required, current_user\n"
        "app = Flask(__name__)\n")


def _authz(code, name="a.py"):
    return sorted((v.line, v.cwe_id) for v in
                  FrameScanner(language="python", verify=False).scan(HEAD + code, name).vulnerabilities
                  if v.cwe_id in ("CWE-862", "CWE-863", "CWE-639"))


def test_grant_scoped_on_one_path_unscoped_on_another_is_flagged():
    # owner check grants (scoped); a shared-reference grant does not bind the caller (unsound).
    code = (
        "def has_access(file):\n"
        "    if file.user_id == current_user.id:\n"
        "        return True\n"
        "    for sc in lookup_shared(file.id):\n"
        "        if sc.active:\n"
        "            return True\n"
        "    return False\n"
    )
    out = _authz(code)
    assert any(cwe == "CWE-863" for _, cwe in out), out


def test_every_grant_scoped_is_not_flagged():
    # Both grant paths bind the resource to the caller: sound, no finding.
    code = (
        "def has_access(file):\n"
        "    if file.user_id == current_user.id:\n"
        "        return True\n"
        "    if file.team_id == current_user.id:\n"
        "        return True\n"
        "    return False\n"
    )
    assert not any(cwe == "CWE-863" for _, cwe in _authz(code))


def test_no_caller_identity_is_not_an_authz_decision():
    # No principal in scope: this is not an authorization decision, so it is never flagged.
    code = (
        "def is_ok(file):\n"
        "    if file.user_id == file.owner_id:\n"
        "        return True\n"
        "    if file.public:\n"
        "        return True\n"
        "    return False\n"
    )
    assert not any(cwe == "CWE-863" for _, cwe in _authz(code))


def test_soundness_lead_is_published_for_the_hunt():
    # The flagged decision function is also published on program.authz_soundness and surfaced to
    # the agentic hunt as a lead (build_index -> EngineIndex.soundness_leads), so the agent is
    # handed the helper where the real authorization logic lives instead of having to find it.
    from frame.sil.frontends.python_frontend import PythonFrontend
    from frame.sil.translator import SILTranslator
    from frame.sil.llm_hunt import build_index
    code = (HEAD +
            "def has_access(file):\n"
            "    if file.user_id == current_user.id:\n"
            "        return True\n"
            "    for sc in lookup_shared(file.id):\n"
            "        if sc.active:\n"
            "            return True\n"
            "    return False\n")
    prog = PythonFrontend().translate(code, "a.py")
    translator = SILTranslator(prog)
    checks = translator.translate_program()
    leads = getattr(prog, "authz_soundness", [])
    assert any(lead["name"].endswith("has_access") for lead in leads), leads
    idx = build_index(prog, [], repo_root="")
    assert any(x["name"].endswith("has_access") for x in idx.soundness_leads)
    assert checks is not None


def test_function_that_returns_the_comparison_is_not_a_candidate():
    # `return <expr>` (not a literal True) is already the scoped predicate, not an explicit grant.
    code = (
        "def has_access(file):\n"
        "    return file.user_id == current_user.id\n"
    )
    assert not any(cwe == "CWE-863" for _, cwe in _authz(code))


def test_django_get_object_or_404_reaches_a_resource():
    # Django's documented fetch-by-field shortcut is the primary IDOR surface in Django apps;
    # before this it was invisible to the resource-reach analysis (so a handler using it read as
    # `reaches_resource: false`, hiding it from both the missing-authz check and the hunt's suspect
    # list). It is keyed on the canonical import id, so a project function of the same name is not
    # caught. Regression for BAC-Bench wagtail (get_object -> get_object_or_404(self.model, pk=...)).
    from frame.sil.frontends.python_frontend import PythonFrontend
    from frame.sil.translator import SILTranslator

    def reaches(code):
        prog = PythonFrontend().translate(code, "v.py")
        t = SILTranslator(prog)
        t.translate_program()
        return t._proc_reaches_resource(prog.procedures["view"])

    assert reaches("from django.shortcuts import get_object_or_404\n"
                   "def view(request, pk):\n    return get_object_or_404(Thing, pk=pk)\n")
    assert reaches("from django.shortcuts import get_list_or_404\n"
                   "def view(request, pk):\n    return get_list_or_404(Thing, owner=pk)\n")
    # A project's own function that happens to share the name is NOT a resource select.
    assert not reaches("def get_object_or_404(m, **k):\n    return 1\n"
                       "def view(request, pk):\n    return get_object_or_404(Thing, pk=pk)\n")
