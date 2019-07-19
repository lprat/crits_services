from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^stix_validator/$', views.stix_validator, name='stix_validator_service-views-stix_validator'),
    url(r'^validate/$', views.validate, name='stix_validator_service-views-validate'),
]
