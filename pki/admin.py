from __future__ import absolute_import, division, print_function, unicode_literals

from django import forms
from django.conf.urls import url
from django.contrib import admin
from django.core.urlresolvers import reverse

from pki.lib.models import JSONCharField

from .models import Entity, Authority, Certificate, CRL, SigningRequest
from . import views


class PKIAdmin(admin.ModelAdmin):
    """ Shared configuration. """
    formfield_overrides = {
        JSONCharField: {'widget': forms.TextInput(attrs={'size': 100})},
    }

    def admin_view(self, view_cls):
        return self.admin_site.admin_view(view_cls.as_view(current_app=self.admin_site.name))


#
# Entity
#

class EntityRoleFilter(admin.SimpleListFilter):
    title = "Role"
    parameter_name = 'role'

    def lookups(self, request, model_admin):
        return [
            (Entity.ROLE_NONE, "None"),
            (Entity.ROLE_CLIENT, "Client"),
            (Entity.ROLE_SERVER, "Server"),
            (Entity.ROLE_BOTH, "Both"),
        ]

    def queryset(self, request, queryset):
        role = self.value()
        if role is not None:
            role = int(self.value())

            if role == Entity.ROLE_CLIENT:
                queryset = queryset.role_client()
            elif role == Entity.ROLE_SERVER:
                queryset = queryset.role_server()
            else:
                queryset = queryset.filter(role=role)

        return queryset


class EntityAdmin(PKIAdmin):
    list_display = ['__unicode__', 'issuer', 'role', 'renew_link']
    list_filter = [EntityRoleFilter]
    search_fields = ['dn']

    raw_id_fields = ['issuer']

    def renew_link(self, entity):
        if Certificate.objects.filter(entity=entity).exists():
            href = reverse('admin:pki2_entity_renew', kwargs={'pk': entity.pk})
            link = '<a href={}>renew<?a>'.format(href)
        else:
            link = ''

        return link
    renew_link.short_description = ""
    renew_link.allow_tags = True

    def get_urls(self):
        extra = [
            url('^(?P<pk>\d+)/renew/$', self.admin_view(views.RenewEntityView), name='pki2_entity_renew'),
        ]

        return extra + super(EntityAdmin, self).get_urls()


#
# Authority
#

class AuthorityAdmin(PKIAdmin):
    list_display = ['__unicode__', 'unique_id', 'issuer', 'is_cert_signer', 'is_crl_signer']
    list_filter = ['is_cert_signer', 'is_crl_signer']
    search_fields = ['unique_id', 'dn']

    raw_id_fields = ['issuer']


#
# Certificate
#

class CertificateRevokedFilter(admin.SimpleListFilter):
    title = "Revoked"
    parameter_name = 'is_revoked'

    def lookups(self, request, model_admin):
        return [
            ('0', "False"),
            ('1', "True"),
        ]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            queryset = queryset.exclude(revoked_at__isnull=bool(int(value)))

        return queryset


def revoke_cert(modeladmin, request, queryset):
    queryset.revokable().revoke()
revoke_cert.short_description = "Revoke"


class CertificateAdmin(PKIAdmin):
    list_display = ['serial_hex', 'entity_link', 'state', 'valid_at', 'expires_at', 'is_revoked', 'download_link']
    ordering = ['-valid_at']
    list_filter = ['state', CertificateRevokedFilter]
    search_fields = ['entity__dn']
    actions = [revoke_cert]

    readonly_fields = ['serial', 'entity', 'created_at', 'valid_at', 'expires_at', 'cert_file']

    def serial_hex(self, cert):
        return "{0:016x}".format(cert.serial)
    serial_hex.short_description = "Serial"

    def entity_link(self, cert):
        href = reverse('admin:pki2_entity_change', args=(cert.entity.pk,))

        return '<a href={0}>{1}<?a>'.format(href, cert.entity)
    entity_link.allow_tags = True
    entity_link.short_description = "Entity"

    def download_link(self, cert):
        if cert.cert_file:
            link = '<a href="{0}">download</a>'.format(cert.cert_file.url)
        else:
            link = ''

        return link
    download_link.allow_tags = True


#
# CRL
#

def refresh_crl(modeladmin, request, queryset):
    queryset.refresh()
refresh_crl.short_description = "Refresh"


class CRLAdmin(PKIAdmin):
    list_display = ['authority', 'this_update', 'next_update', 'ttl']
    search_fields = ['authority__dn']
    actions = [refresh_crl]

    raw_id_fields = ['issuer', 'authority']
    readonly_fields = ['number', 'crl_file']


#
# SigningRequest
#

class SigningRequestAdmin(PKIAdmin):
    list_display = ['entity', 'created_at', 'message', 'approve_link']

    raw_id_fields = ['entity']

    def approve_link(self, req):
        href = reverse('admin:pki2_signingrequest_approve', kwargs={'pk': req.pk})

        return '<a href={}>approve<?a>'.format(href)
    approve_link.short_description = ""
    approve_link.allow_tags = True

    def get_urls(self):
        extra = [
            url('^(?P<pk>\d+)/approve/$', self.admin_view(views.ApproveRequestView), name='pki2_signingrequest_approve'),
        ]

        return extra + super(SigningRequestAdmin, self).get_urls()


admin.site.register(Entity, EntityAdmin)
admin.site.register(Authority, AuthorityAdmin)
admin.site.register(Certificate, CertificateAdmin)
admin.site.register(CRL, CRLAdmin)
admin.site.register(SigningRequest, SigningRequestAdmin)
