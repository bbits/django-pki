from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import timedelta
from functools import partial

from asn1crypto import pem
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseBadRequest, HttpResponseRedirect
from django.template.response import TemplateResponse
from django.views.generic.detail import SingleObjectMixin
from django.views.generic.edit import FormView
from django.views.generic.base import View

from pki.lib.properties import lazy_property

from .forms import RenewEntityForm, ApproveRequestForm
from .models import Entity, Authority, Certificate, SigningRequest


class AuthorityCert(View):
    """
    Public view to download a CA certificate.
    """
    def get(self, request, unique_id, form):
        try:
            authority = Authority.objects.get(unique_id=unique_id)
        except Authority.DoesNotExist:
            cert = None
        else:
            cert = authority.current_certificate()

        if cert is not None:
            if form == 'pem':
                response = HttpResponse(cert.pem(), content_type='application/x-pem-file')
            elif form == 'cer':
                response = HttpResponse(cert.der, content_type='application/pkix-cert')
            else:
                response = HttpResponseBadRequest()
        else:
            response = HttpResponseNotFound()

        return response


#
# Django admin views
#

class AdminViewMixin(object):
    """ Common code for custom admin views. """
    current_app = None

    @property
    def response_class(self):
        return partial(TemplateResponse, current_app=self.current_app)


class RenewEntityView(FormView, SingleObjectMixin, AdminViewMixin):
    template_name = 'pki2/entity/renew.dhtml'
    model = Entity
    form_class = RenewEntityForm

    def get_context_data(self, **kwargs):
        context = super(RenewEntityView, self).get_context_data(**kwargs)
        context['meta'] = Entity._meta

        return context

    def get_success_url(self):
        if self.req is not None:
            url = reverse('admin:pki2_signingrequest_approve', kwargs={'pk': self.req.pk})
        else:
            url = reverse('admin:pki2_entity_changelist')

        return url

    def form_valid(self, form):
        entity = self.object
        issuer = entity.get_issuer()
        cert = Certificate.objects.filter(entity=entity).order_by('-valid_at').first()

        days = form.cleaned_data['days']
        emails = cert.subject_alt_emails
        domains = cert.subject_alt_domains
        ips = cert.subject_alt_ips

        if issuer.is_private_key_encrypted():
            self.req = SigningRequest.objects.create(
                entity=entity,
                key_pem=pem.armor('PUBLIC KEY', cert.public_key_info().dump()),
                days=days, emails=emails, domains=domains, ips=ips
            )
            self.cert = None
        else:
            self.cert = issuer.issue_cert(
                entity, cert.public_key_info(),
                expires_at=timedelta(days=days),
                emails=emails, domains=domains, ips=ips
            )
            self.req = None

        return HttpResponseRedirect(self.get_success_url())

    @lazy_property
    def object(self):
        return self.get_object()


class ApproveRequestView(FormView, SingleObjectMixin, AdminViewMixin):
    template_name = 'pki2/req/approve.dhtml'
    model = SigningRequest
    form_class = ApproveRequestForm

    def get_context_data(self, **kwargs):
        context = super(ApproveRequestView, self).get_context_data(**kwargs)
        context['meta'] = SigningRequest._meta

        return context

    def get_success_url(self):
        return reverse('admin:pki2_signingrequest_changelist')

    def form_valid(self, form):
        req = self.object
        password = form.cleaned_data['password'] or None

        with transaction.atomic():
            certificate = req.issue(password)
            if certificate is not None:
                req.delete()

        if certificate is not None:
            response = HttpResponseRedirect(self.get_success_url())
        else:
            response = self.form_invalid(form)

        return response

    @lazy_property
    def object(self):
        return self.get_object()
