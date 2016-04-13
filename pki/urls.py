from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'^ca/(?P<unique_id>[^\s/]+)\.(?P<form>cer|pem)$', views.AuthorityCert.as_view()),
]
