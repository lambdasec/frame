from django.db.models.expressions import RawSQL
from django.http import FileResponse, HttpResponse, HttpResponseRedirect
from django.template import Context, Template
from django.utils.safestring import mark_safe
from django.views import View
from django.views.generic import TemplateView

from catalog import queries
from catalog.models import Product


class ProductListView(View):
    def get(self, request):
        sort = request.GET.get("sort", "name")
        products = Product.objects.extra(order_by=[sort])  # frame-expect: CWE-89
        return HttpResponse(", ".join(p.name for p in products))


class ProductSearchView(View):
    def get(self, request, category):
        return HttpResponse(str(queries.in_category(category)))


class BannerView(TemplateView):
    template_name = "banner.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["banner"] = mark_safe(self.request.GET.get("banner", ""))  # frame-expect: CWE-79
        return ctx


def annotate(request):
    expr = RawSQL("SELECT count(*) FROM orders WHERE sku = '%s'" % request.GET["sku"], [])  # frame-expect: CWE-89
    return HttpResponse(str(Product.objects.annotate(n=expr).count()))


def render_notice(request):
    tpl = Template(request.POST["body"])  # frame-expect: CWE-1336
    return HttpResponse(tpl.render(Context({})))


def after_login(request):
    return HttpResponseRedirect(request.GET.get("next", "/"))  # frame-expect: CWE-601


def invoice(request, number):
    return FileResponse(open("/srv/invoices/" + number + ".pdf", "rb"))  # frame-expect: CWE-22
