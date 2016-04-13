"""
Celery tasks?
"""
from __future__ import absolute_import, division, print_function, unicode_literals

from pki.lib.timezone import now

from .models import Certificate, CRL


def retire_certs():
    """
    Periodically marks expired certificates as RETIRED.

    Note that this does not handle revoked certificates. There's a weird rule
    that says revoked certificates must appear in one final CRL after they
    expire, so this is handled in Authority.refresh_crl.

    """
    count = Certificate.objects.filter(state=Certificate.ISSUED,
                                       expires_at__lte=now(),
                                       revoked_at__isnull=True) \
                               .update(state=Certificate.RETIRED)

    return count


def refresh_crls():
    count = CRL.objects.filter(refresh_at__lte=now()).refresh()

    return count
