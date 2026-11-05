"""Handlers a framework base class provides (`[[provided_action]]`; frame/sil/llm_hunt.py
`_provided_handlers`): a DRF viewset answers `list` / `retrieve` / ... with DRF's own code over
the class's queryset even when the class writes none of them. A unit listed only the methods
written in the class, so the agent never judged the inherited `list` of a viewset whose
`queryset = Model.objects.all()` was the bug. Real frontend and packs on small snippets."""

from frame.sil.hunt_units import plan_units
from frame.sil.llm_hunt import _corroborated, _unit_intro, build_index
from frame.sil.scanner import FrameScanner


def _programs(files):
    progs = []
    for name, code in files.items():
        sc = FrameScanner(language="python", verify=False, hunt_authz=True)
        sc._collecting_hunt_programs = True
        sc.scan(code, name)
        progs += sc._hunt_programs
    return progs


VIEWS = """from rest_framework import viewsets
from rest_framework.mixins import DestroyModelMixin, UpdateModelMixin
from .models import Addon, Note


class AddonViewSet(viewsets.ReadOnlyModelViewSet, UpdateModelMixin, DestroyModelMixin):
    queryset = Addon.objects.all()
    serializer_class = None

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        return super().destroy(request, *args, **kwargs)


class NoteViewSet(viewsets.ModelViewSet):
    queryset = Note.objects.all()


class Helper:
    def list(self):
        return []
"""


def _provided(index):
    return {h.name: h for h in index.handlers if h.provided_by}


def test_inherited_actions_become_members_and_written_ones_do_not():
    index = build_index(_programs({"views.py": VIEWS}), [], "")
    got = _provided(index)
    assert {n for n in got if n.startswith("AddonViewSet.")} == {
        "AddonViewSet.list", "AddonViewSet.retrieve", "AddonViewSet.partial_update"}
    assert got["AddonViewSet.list"].provided_by == "rest_framework.viewsets.ReadOnlyModelViewSet"
    assert "queryset" in got["AddonViewSet.list"].decided_by
    # a viewset that writes nothing still answers six requests
    assert {n for n in got if n.startswith("NoteViewSet.")} == {
        f"NoteViewSet.{a}" for a in ("list", "retrieve", "create", "update", "partial_update", "destroy")}
    assert not any(n.startswith("Helper.") for n in got)        # not a framework class
    assert got["NoteViewSet.list"].line == VIEWS.splitlines().index("class NoteViewSet(viewsets.ModelViewSet):") + 1


def test_they_join_the_class_unit_and_the_agent_is_told_what_decides_them():
    index = build_index(_programs({"views.py": VIEWS}), [], "")
    units, _ = plan_units(index, "python")
    addon = next(u for u in units if u.id.startswith("views.py::AddonViewSet"))
    assert {"AddonViewSet.list", "AddonViewSet.retrieve", "AddonViewSet.update"} <= set(addon.names())
    note = next(u for u in units if u.id == "views.py::NoteViewSet")
    assert len(note.names()) == 6

    class Ctx:
        repo_root = ""
    intro = _unit_intro(Ctx(), addon, "")
    row = next(r for r in intro.splitlines() if r.startswith("- AddonViewSet.list"))
    assert "NOT WRITTEN IN THE CLASS" in row and "ReadOnlyModelViewSet" in row
    assert "set in the class: queryset" in row


def test_an_inherited_member_is_never_engine_backed():
    index = build_index(_programs({"views.py": VIEWS}), [], "")
    f = {"handler": "NoteViewSet.list", "file": "views.py", "engine_backed": True}
    assert _corroborated(f, index) is False


def test_bases_are_followed_through_project_classes_in_other_files():
    base = ("from rest_framework import viewsets\n\n\n"
            "class ProjectViewSet(viewsets.ModelViewSet):\n"
            "    def list(self, request):\n"
            "        return super().list(request)\n")
    child = ("from rest_framework import viewsets\n"
             "from .base import ProjectViewSet\n"
             "from .models import Doc\n\n\n"
             "class DocViewSet(ProjectViewSet):\n"
             "    queryset = Doc.objects.all()\n")
    got = _provided(build_index(_programs({"base.py": base, "child.py": child}), [], ""))
    names = {n for n in got if n.startswith("DocViewSet.")}
    # list is written by the project's base (a real procedure there), the rest come from DRF
    assert names == {f"DocViewSet.{a}" for a in ("retrieve", "create", "update", "partial_update", "destroy")}


def test_an_ambiguous_project_base_is_not_guessed():
    a = "from rest_framework import viewsets\n\n\nclass Base(viewsets.ModelViewSet):\n    pass\n"
    b = "class Base:\n    pass\n"
    child = ("from rest_framework import viewsets\nfrom .a import Base\n\n\n"
             "class V(Base):\n    pass\n")
    got = _provided(build_index(_programs({"a.py": a, "b.py": b, "child.py": child}), [], ""))
    assert not any(n.startswith("V.") for n in got)


def test_nothing_without_the_framework():
    code = ("class ModelViewSet:\n    pass\n\n\nclass V(ModelViewSet):\n    queryset = 1\n")
    assert not _provided(build_index(_programs({"v.py": code}), [], ""))
