import os

from django.db.models.expressions import RawSQL
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.template import Context, Template
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.views import View
from django.views.generic import TemplateView

from catalog import queries
from catalog.models import Product


class ProductListView(View):
    def get(self, request):
        sort = request.GET.get("sort", "name")
        products = Product.objects.order_by(sort if sort in ("name", "category") else "name")
        return HttpResponse(", ".join(p.name for p in products))


class ProductSearchView(View):
    def get(self, request, category):
        return HttpResponse(str(queries.in_category(category)))


class BannerView(TemplateView):
    template_name = "banner.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["banner"] = mark_safe(escape(self.request.GET.get("banner", "")))
        return ctx


def annotate(request):
    expr = RawSQL("SELECT count(*) FROM orders WHERE sku = %s", [request.GET["sku"]])
    return HttpResponse(str(Product.objects.annotate(n=expr).count()))


def render_notice(request):
    tpl = Template("<p>{{ body }}</p>")
    return HttpResponse(tpl.render(Context({"body": request.POST["body"]})))


def after_login(request):
    return HttpResponseRedirect("/")


def invoice(request, number):
    filename = os.path.basename(number) + ".pdf"
    return FileResponse(open(os.path.join("/srv/invoices", filename), "rb"))
