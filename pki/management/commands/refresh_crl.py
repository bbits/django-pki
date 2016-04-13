from __future__ import absolute_import, division, print_function, unicode_literals

from django.core.management.base import BaseCommand, CommandError

from pki.models import CRL


class Command(BaseCommand):
    help = """ Refresh one or more CRLs. """

    def add_arguments(self, parser):
        parser.add_argument('unique_ids', nargs='*', metavar='unique_id', help="Refresh the CRL for a particular authority.")

        group = parser.add_argument_group('refresh_crl')
        group.add_argument('-a', '--all', action='store_true', dest='refresh_all', help="Refresh all CRLs.")

    def handle(self, unique_ids, refresh_all, **options):
        if refresh_all:
            crl_set = CRL.objects.all()
        elif len(unique_ids) > 0:
            crl_set = CRL.objects.filter(authority__unique_id__in=unique_ids)
        else:
            raise CommandError("Must specify at least one unique_id or -a")

        crl_set.refresh()
