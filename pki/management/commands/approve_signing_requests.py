from __future__ import absolute_import, division, print_function, unicode_literals

from django.core.management.base import BaseCommand

from pki.models import SigningRequest


class Command(BaseCommand):
    help = """Approve all outstanding signing requests."""

    def add_arguments(self, parser):
        group = parser.add_argument_group("approve_signing_requests")
        group.add_argument('--authority', '-a', help="Only approve requests for the named authority (unique_id).")
        group.add_argument('--password', '-p', help="Password to unlock private keys, if necessary.")

    def handle(self, authority, password, **options):
        req_set = SigningRequest.objects.all()
        if authority is not None:
            req_set = req_set.filter(entity__issuer__unique_id=authority)

        for req in req_set.iterator():
            req.issue(password)
            req.delete()
