from django.contrib.auth.decorators import login_required
from django.urls import path, re_path

from . import views

urlpatterns = [
    path("products/", views.ProductListView.as_view()),
    path("products/<str:category>/", views.ProductSearchView.as_view()),
    path("banner/", views.BannerView.as_view()),
    path("annotate/", views.annotate),
    path("notice/", login_required(views.render_notice)),
    path("after-login/", views.after_login, name="after-login"),
    re_path(r"^invoices/(?P<number>[0-9]+)/$", views.invoice),
]
