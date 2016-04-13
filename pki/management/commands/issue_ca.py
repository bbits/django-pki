from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError

from pki.models import Authority, KeyDecryptionError


class Command(BaseCommand):
    help = """Issue a certificate for a pki2.Authority. This is really only
              intended for bootstrapping a deployment. Certificates will not
              normally be issued this way."""

    def add_arguments(self, parser):
        parser.add_argument('unique_id', help="The unique_id of the authority.")

        group = parser.add_argument_group('issue_ca')
        group.add_argument('--days', '-d', type=int, default=3650, help="Certificate validity in days.")
        group.add_argument('--issuer-password', '-p', help="Password for the issuer's private key, if any.")
        group.add_argument('--subject-password', '-P', help="Password for the subject's private key, if any.")
        group.add_argument('--force', '-f', action='store_true', help="Issue a new cert even if one exists.")

    def handle(self, unique_id, days, issuer_password, subject_password, force, **options):
        try:
            authority = Authority.objects.get(unique_id=unique_id)
        except Authority.DoesNotExist as e:
            raise CommandError(unicode(e).encode('utf-8'))

        issuer = authority.issuer
        if issuer is None:
            issuer = authority

        if force or (authority.current_certificate() is None):
            try:
                pub = authority.public_key_info(subject_password)
                issuer.issue_cert(authority, pub, expires_at=timedelta(days=days), password=issuer_password)
            except KeyDecryptionError:
                raise CommandError("Error decrypting private key.")
