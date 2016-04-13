from __future__ import absolute_import, division, print_function, unicode_literals

from datetime import timedelta
import unittest

from asn1crypto import csr, pem, keys
from django.db.models.signals import post_save
from django.test import TestCase
from oscrypto import asymmetric

from pki.lib.timezone import Now, now, utcdatetime

from . import tasks
from .lib import verify_csr, PkiSlice
from .models import Entity, Authority, Certificate, CRL, SigningRequest, NoValidCertificate, KeyDecryptionError


class PkiTestCase(TestCase):
    def setUp(self):
        super(PkiTestCase, self).setUp()

        self.certs = []
        self.crls = []
        post_save.connect(self._handle_new_cert, sender=Certificate)
        post_save.connect(self._handle_new_crl, sender=CRL)

    def tearDown(self):
        post_save.disconnect(self._handle_new_cert, sender=Certificate)
        post_save.disconnect(self._handle_new_crl, sender=CRL)

        # Clean up files
        for cert in self.certs:
            cert.cert_file.delete(save=False)
        for crl in self.crls:
            crl.crl_file.delete(save=False)

        super(PkiTestCase, self).tearDown()

    #
    # Standard cases
    #

    def test_anchor(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, cert = self.issue_anchor(is_crl_signer=False)

        asn_cert = cert.asn_cert
        self.assertEqual(asn_cert.key_usage_value.native, set(['key_cert_sign']))
        self.assertEqual(asn_cert.extended_key_usage_value, None)
        self.assertFalse(anchor.is_private_key_encrypted())
        self.assertEqual(cert.subject_alt_emails, [])

    def test_ca(self):
        with Now(utcdatetime(2000, 1, 1)):
            ca, cert = self.issue_ca()

        asn_cert = cert.asn_cert
        self.assertEqual(asn_cert.key_usage_value.native, set(['key_cert_sign', 'crl_sign']))
        self.assertEqual(asn_cert.extended_key_usage_value, None)
        self.assertEqual(ca.as_authority(), ca)

    def test_server_entity(self):
        with Now(utcdatetime(2000, 1, 1)):
            entity, cert = self.issue_entity('Server 1', domains=['vpn.example.com'], role=Entity.ROLE_SERVER)

        asn_cert = cert.asn_cert
        self.assertEqual(asn_cert.key_usage_value.native, set(['digital_signature', 'key_encipherment']))
        self.assertEqual(asn_cert.extended_key_usage_value.native, ['server_auth'])
        self.assertEqual(asn_cert.subject_alt_name_value.native, ['vpn.example.com'])
        self.assertEqual(cert.subject_alt_domains, ['vpn.example.com'])
        self.assertEqual(list(entity.chain()), [entity.issuer, entity.issuer.issuer])
        self.assertEqual(entity.as_authority(required=False), entity)
        with self.assertRaises(Authority.DoesNotExist):
            entity.as_authority(required=True)
        with Now(utcdatetime(2000, 1, 1)):
            self.assertEqual(entity.intermediate_certificates(), [entity.issuer.current_certificate()])

    def test_client_entity(self):
        with Now(utcdatetime(2000, 1, 1)):
            entity, cert = self.issue_entity('Client 1', role=Entity.ROLE_CLIENT)

        asn_cert = cert.asn_cert
        self.assertEqual(asn_cert.key_usage_value.native, set(['digital_signature']))
        self.assertEqual(asn_cert.extended_key_usage_value.native, ['client_auth'])
        self.assertEqual(Certificate.objects.revokable().count(), 3)

    def test_role_filters(self):
        with Now(utcdatetime(2000, 1, 1)):
            ca, _ = self.issue_ca()
            client, _ = self.issue_entity('Client', role=Entity.ROLE_CLIENT)
            server, _ = self.issue_entity('Server', role=Entity.ROLE_SERVER)
            both, _ = self.issue_entity('Both', role=Entity.ROLE_BOTH)

        self.assertEqual(Entity.objects.role_client().count(), 2)
        self.assertEqual(Entity.objects.role_server().count(), 2)

    def test_encrypted_key(self):
        key = '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,6090B5C039E3C08382031D7F3621E228\n\nDyD1DfG+4BRpdCMSOyNOC/m2RdksrbKIXWoTQu+bnifHsKfbE8MB9QFERzIXU3DV\nQ8B/ZB/I2HsdtpFAU+Gxn5iycRKEefnzRltZe/U9wSlZi53c9sy8AVySffqRy5Ly\nrbicqWKTbIx29Ip+a8Xm2OupvluWWP322zbr6faU2ZtTtW5DdZdvpsaT/mb1DuP9\nGKQUUmhvHOOL6NrOhElFTis6bAZJ8tLIjmJcQu0uHc8gVat/76t94l4CJ9N99DTT\n2yWLF2nMbxC6BT2BTbeRCANoY2LZ2ewqAINYMAz+deqhbIhK4Tbfn7IpAL9At7ec\nh/DoUhuMOwx4NEq3MWQiqxe/ZmyxGAskCBdTJY+f/2NepifX38GaNqcL0S2gsher\nMQNpteLgjqAgxOla1GZcp0Ns9ZzEBYfwxXbvm+wREVTmbM2bdgHiMpWg5N2i55UO\n+s6pMzmWGFQ9p+KB7FbCEYULnN12S71oguX20Q6z8obMH0KlZp5waPaSbjpm2Vp8\nQxcGMKWXMCrYy46w9+/TbB4RG/k7nQUNmaZFURTMrDnCe6L5z8z3l8fkJIqHqOQr\nka/egYy9gdMWirahcctKzA7FwBgr/Y37AAeaOrBs4MvtROIDUXRXcNfrRVYWjkIQ\n1vSdD5XNiRHL1tFOadlm0B25kwtCk5TQooZktIN2Pl5lL1Sznq3w0f26JTyjHWPo\nvcluoAvZzQYFeAN16ytNHaGBzlZ3LGPjFC5OYnHsL4DHK806rzZPCahOzq0Vzop7\ncVIHPj+d7Jfhcd41NQ9p3/tl0dKmj/VU8I+atzQAHIk=\n-----END RSA PRIVATE KEY-----\n'

        authority = Authority.objects.create(dn={'common_name': 'Anchor'}, key_pem=key)

        self.assertTrue(authority.is_private_key_encrypted())
        with self.assertRaises(KeyDecryptionError):
            authority.private_key()
        self.assertIsNotNone(authority.private_key('password'))
        self.assertIsNotNone(authority.private_key_info('password'))
        self.assertIsNotNone(authority.public_key_info('password'))

    def test_empty_crl(self):
        with Now(utcdatetime(2000, 1, 1)):
            crl = self.new_crl()
            crl.refresh()
            asn_crl = crl.asn_crl()

        self.assertEqual(asn_crl.crl_number_value.native, crl.number)
        self.assertEqual(asn_crl['tbs_cert_list']['this_update'].native, utcdatetime(2000, 1, 1))
        self.assertEqual(asn_crl['tbs_cert_list']['next_update'].native, utcdatetime(2000, 1, 1) + timedelta(seconds=crl.ttl))
        self.assertEqual(asn_crl['tbs_cert_list']['revoked_certificates'].native, [])

    def test_revocation(self):
        with Now(utcdatetime(2000, 1, 1)):
            ca, _ = self.issue_ca()
            crl = self.new_crl(ca)
            crl_url = crl.url()

            # Retired revoked certificate.
            entity, cert = self.issue_entity('Test', ca)
            cert.revoked_at = now() + timedelta(1)
            cert.state = Certificate.RETIRED
            cert.save()

        # Nonsensical revoked reservation.
        cert = Certificate.objects.reserve(entity, utcdatetime(2000, 2, 1), utcdatetime(2000, 5, 1))
        cert.revoked_at = utcdatetime(2000, 2, 1)
        cert.save()

        # Normal revoked certificate.
        with Now(utcdatetime(2000, 3, 1)):
            cert = ca.issue_cert(entity, self.keys['entity'][0], expires_at=timedelta(days=90))
        with Now(utcdatetime(2000, 3, 2)):
            cert.revoke()

        with Now(utcdatetime(2000, 3, 2)):
            tasks.refresh_crls()

        crl = CRL.objects.get(pk=crl.pk)
        asn_crl = crl.asn_crl()
        self.assertEqual(crl.url(), crl_url)
        self.assertEqual(Certificate.objects.revokable().count(), 2)
        self.assertEqual(Certificate.objects.issued().revoked().count(), 1)
        self.assertEqual(ca.issued_certificate_set.count(), 3)
        self.assertEqual(crl.revoked_certificate_set.count(), 1)
        self.assertEqual(
            [rc['user_certificate'] for rc in asn_crl['tbs_cert_list']['revoked_certificates'].native],
            [cert.serial]
        )
        self.assertTrue(pem.detect(crl.pem()))

    def test_bulk_revocation(self):
        with Now(utcdatetime(2000, 1, 1)):
            entity, _ = self.issue_entity('Entity')

        with Now(utcdatetime(2000, 1, 2)):
            entity.certificate_set.revokable().revoke()

        self.assertEqual(Certificate.objects.revoked().count(), 1)

    def test_indirect_revocation(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor()
            authority, _ = self.issue_ca(anchor, 'CA1')
            issuer, _ = self.issue_ca(anchor, 'CA2')
            crl = self.new_crl(authority, issuer)

            entity, cert = self.issue_entity('Test', authority)
            revoked_at = now() + timedelta(seconds=60)
            cert.revoked_at = revoked_at
            cert.save()

            issuer.refresh_crl(crl)
            asn_crl = crl.asn_crl()

        self.assertEqual(asn_crl['tbs_cert_list']['issuer'].native, {'common_name': 'CA2'})

        idps = [extn for extn in asn_crl['tbs_cert_list']['crl_extensions'] if extn['extn_id'].native == 'issuing_distribution_point']
        self.assertEqual(len(idps), 1)
        self.assertTrue(idps[0]['extn_value'].parsed['indirect_crl'].native)

        self.assertEqual(
            asn_crl['tbs_cert_list']['revoked_certificates'][0].certificate_issuer_value.native,
            [{'common_name': 'CA1'}]
        )

    def test_retire_revoked(self):
        with Now(utcdatetime(2000, 1, 1)):
            ca, _ = self.issue_ca()
            crl = self.new_crl(ca)
            entity1, _ = self.issue_entity('One', ca)
            entity2, _ = self.issue_entity('Two', ca)
            ca.refresh_crl(crl)

        self.assertEqual(ca.issued_certificate_set.revoked().count(), 0)
        self.assertEqual(ca.issued_certificate_set.retired().count(), 0)

        with Now(utcdatetime(2000, 1, 2)):
            entity1.certificate_set.update(revoked_at=now())
            ca.refresh_crl(crl)

        self.assertEqual(ca.issued_certificate_set.revoked().count(), 1)
        self.assertEqual(ca.issued_certificate_set.retired().count(), 0)

        with Now(utcdatetime(2000, 7, 1)):
            ca.refresh_crl(crl)

        self.assertEqual(ca.issued_certificate_set.revoked().count(), 1)
        self.assertEqual(ca.issued_certificate_set.retired().count(), 1)

    def test_pki_slice(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor(is_crl_signer=False)
            crl_anchor, _ = self.issue_anchor(is_cert_signer=False)
            anchor_crl = self.new_crl(anchor, crl_anchor)
            ca, _ = self.issue_ca(anchor)
            ca_crl = self.new_crl(ca)
            entity, _ = self.issue_entity('Entity', ca)

            # Unrelated
            entity2, _ = self.issue_entity('Entity2')
            self.new_crl(entity2.issuer)

        pki = PkiSlice(entity)
        self.assertEqual(frozenset(pki.anchors()), frozenset([anchor, crl_anchor]))
        self.assertEqual(frozenset(pki.intermediates()), frozenset([ca]))
        self.assertEqual(frozenset(pki.extras()), frozenset([ca]))
        self.assertEqual(frozenset(pki.crls()), frozenset([ca_crl, anchor_crl]))

    def test_unicode_coverage(self):
        with Now(utcdatetime(2000, 1, 1)):
            unicode(self.issue_anchor({'common_name': 'Anchor', 'dn_qualifier': 'Qualifier'})[0])
            unicode(self.issue_anchor({'common_name': 'Anchor'})[0])
            unicode(self.issue_anchor({'organizational_unit_name': 'Widgets'})[0])
            unicode(self.issue_anchor({'organization_name': 'Acme'})[0])
            unicode(self.issue_anchor({'domain_component': 'acme'})[0])

    def test_coverage(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, cert = self.issue_anchor()
            reissued = cert.issue(anchor, cert.asn_cert)

            self.assertEqual(Certificate.objects.issued().count(), 1)
            self.assertEqual(Certificate.objects.revoked().count(), 0)
            self.assertEqual(Certificate.objects.revokable().count(), 1)
            self.assertEqual(Certificate.objects.expired().count(), 0)
            self.assertTrue(pem.detect(cert.pem()))
            self.assertFalse(cert.is_revoked())
            self.assertEqual(reissued, None)
            self.assertEqual(Entity.objects.get(pk=anchor.pk).get_issuer(), anchor)
            self.assertTrue(isinstance(cert.public_key_info(), keys.PublicKeyInfo))

    def test_signing_request(self):
        anchor, _ = self.issue_anchor()
        req = SigningRequest.objects.create(
            entity=anchor,
            key_pem=self.public_key_pem(self.keys['anchor'][0])
        )
        cert = req.issue()

        self.assertIsNotNone(req.public_key())
        self.assertIsNotNone(cert)

    def test_verify_csr(self):
        csr_pem = b'-----BEGIN CERTIFICATE REQUEST-----\nMIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\nITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAOX7xMqjolAJ39LsPdhPRTxlHxowKyqd6wnHKdT7\nRVjmc9oY2+awntbkxS6qd8xsTipiL69G/eALMZxoWVIJQ6RGjN1ZA/y1IYXDybYc\nIe3vlobMNcuj1a1Oa9JkS9eg4Hd1xRRsREqsIv0rcMXWLOBBAGGfJrTVCTp0YsHG\nOlKWm9pqSLfSZta2R8ULIMyBEYgAi410LNxGdWXbaxbhlZAMS+POrofVQBKwjPzD\nnZhXrE3NKGPy3YW2Shgx/hAwXf4qXWdcA8zpfsgX3xUwhrLCjTFipaKkCJP1s+kc\nsRJ/Ou9RJhvgQqqOFQB6tCL1bPK3OzsGWaTlbEAHRcc7AYUCAwEAAaAAMA0GCSqG\nSIb3DQEBCwUAA4IBAQBtG7zuAHbcHNPd7ZYqqxNFWn0mFw6TuEfF+77aSQnUgk1a\nt2LaxJg+cTVVtC0dE03ita0eWfTF23WItqiDxk2kSaI4HQWgNV6M0EYVYhykrBhe\ngUTS3g3b2ibDVdgrUDQesaF2EEMRXjtYlyA2LimKPrfsPmybFBOosJPrH+YMHpK+\ndTB5X66qDdwuFo0CB3sfadIrSGdDYHurARheM83WS6qCe+UDydduBbzDC2QfBcje\n8XK1ZU7+pKD8XDefVlsWxYyjcKbQlfv7m1FBlHTH8fFNlrvof+slPChLafLvFW1G\n8LaF8Z5pcfz+3opsCMjgNLxZNO28yOAREjTouqiY\n-----END CERTIFICATE REQUEST-----\n'

        req = csr.CertificationRequest.load(pem.unarmor(csr_pem)[2])
        verified = verify_csr(req)

        self.assertTrue(verified)

    @unittest.expectedFailure
    def test_verify_dsa_csr(self):
        """
        I don't know why this fails, but I don't think we actually care about
        DSA.
        """
        csr_pem = b'-----BEGIN CERTIFICATE REQUEST-----\nMIICSzCCAggCAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\nITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCAbgwggEsBgcqhkjO\nOAQBMIIBHwKBgQD4dXOBuPkpOYn3HBjnzSgfZ6+rTNJxfHHebNRH6JkeojvVvssq\ngMeUjJwldVygHM3ewJbHcCTsUYSFXZwtR1F3CHY7NnC8ybYuot4djmDPNcSGNPRY\nmuNfcTaK7VLRGY396kRrL1ExqtZ0eb/1uOFcHz9s3udhqTLRyOWy9GiYiQIVAPZQ\njMRMUgQbAnsfgqFrSXDXhgXrAoGBAI5FAQN8NN++QJUlnEVSIDtdihIwNJ2tAKgS\nFViPne5IDzcKRqIYxwr1Ci7OxinsGMFZqXjT5Y7IlhYosONMzoPXxYXV0gJjS0bj\nxMZrCMHpyuXPN0AyScJpw/hWbVuHcfOVM8/2Nwzpx8VaLYhXTPtWuIsYrP4+CMWI\njr0nzRwaA4GFAAKBgQDl+UDgDprQdutjIhmjEdsyB36rANFoOQDjKVL/Vj6uDbqi\nWfn54qNV7MnI3pAk/nZPh30OmcpSnl0m5E522b63q7WV2tzLlKO7vPOipJyX9GH8\nP/71H/g6UGRbLSVkApWqOw3z+ijxN9bvM+zB8ihXTwlQ96OO+3XmZc1QWjP63aAA\nMAsGCWCGSAFlAwQDAgMwADAtAhUAmYbJM2jyLqRxWO2hgJNC2zqbnsACFDKcB0gM\nW/IY3ZafXVi27kP4dEmr\n-----END CERTIFICATE REQUEST-----\n'

        req = csr.CertificationRequest.load(pem.unarmor(csr_pem)[2])
        verified = verify_csr(req)

        self.assertTrue(verified)

    def test_verify_ecdsa_csr(self):
        csr_pem = b'-----BEGIN CERTIFICATE REQUEST-----\nMIIBiDCB6gIBADBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEh\nMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEG\nBSuBBAAjA4GGAAQBi2M5M4iMZhmBeXx+tGTdqP3MOcDwARhz9we41DHD4GLL7sKO\nR2erxXJbO0L1kpe2EKPWfP9xF1cmMjqoi6K15lgAV5uGTetsr7ITFrNzC+k2mEWX\ntpS/9l3goWq6icrSziZQBNNSqGAeCGbMxrtiblxGpKHE7jLN+ErdX2Jh064in3Gg\nADAKBggqhkjOPQQDAgOBjAAwgYgCQgGtS2jmm4lM38Xxt1aXu8/rTbw+W2gsSQMx\nMLBoyaVJ5sbKpQNgvyNN17MvLnyR0J7NYJSmR+3n7jrWl3S9Q4s85AJCANqjvXn+\nHjCGebrPBF7eaw1dInjDLmO4NqK8+ro028JEEj/JO8aYkZZjUFDFJM3G57Ja/p41\n5ozzR5r8dQ64K/aX\n-----END CERTIFICATE REQUEST-----\n'

        req = csr.CertificationRequest.load(pem.unarmor(csr_pem)[2])
        verified = verify_csr(req)

        self.assertTrue(verified)

    def test_invalid_csr(self):
        csr_pem = b'-----BEGIN CERTIFICATE REQUEST-----\nMIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\nITAfBgNVBAoMGEludgVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBAOX7xMqjolAJ39LsPdhPRTxlHxowKyqd6wnHKdT7\nRVjmc9oY2+awntbkxS6qd8xsTipiL69G/eALMZxoWVIJQ6RGjN1ZA/y1IYXDybYc\nIe3vlobMNcuj1a1Oa9JkS9eg4Hd1xRRsREqsIv0rcMXWLOBBAGGfJrTVCTp0YsHG\nOlKWm9pqSLfSZta2R8ULIMyBEYgAi410LNxGdWXbaxbhlZAMS+POrofVQBKwjPzD\nnZhXrE3NKGPy3YW2Shgx/hAwXf4qXWdcA8zpfsgX3xUwhrLCjTFipaKkCJP1s+kc\nsRJ/Ou9RJhvgQqqOFQB6tCL1bPK3OzsGWaTlbEAHRcc7AYUCAwEAAaAAMA0GCSqG\nSIb3DQEBCwUAA4IBAQBtG7zuAHbcHNPd7ZYqqxNFWn0mFw6TuEfF+77aSQnUgk1a\nt2LaxJg+cTVVtC0dE03ita0eWfTF23WItqiDxk2kSaI4HQWgNV6M0EYVYhykrBhe\ngUTS3g3b2ibDVdgrUDQesaF2EEMRXjtYlyA2LimKPrfsPmybFBOosJPrH+YMHpK+\ndTB5X66qDdwuFo0CB3sfadIrSGdDYHurARheM83WS6qCe+UDydduBbzDC2QfBcje\n8XK1ZU7+pKD8XDefVlsWxYyjcKbQlfv7m1FBlHTH8fFNlrvof+slPChLafLvFW1G\n8LaF8Z5pcfz+3opsCMjgNLxZNO28yOAREjTouqiY\n-----END CERTIFICATE REQUEST-----\n'

        req = csr.CertificationRequest.load(pem.unarmor(csr_pem)[2])
        verified = verify_csr(req)

        self.assertFalse(verified)

    #
    # Tasks
    #

    def test_retire_certs(self):
        with Now(utcdatetime(2000, 1, 1)):
            ca, _ = self.issue_ca()
            _, cert = self.issue_entity('Entity1', ca)
            cert.revoke()
            self.issue_entity('Entity2', ca)
        with Now(utcdatetime(2000, 6, 1)):
            tasks.retire_certs()

        self.assertEqual(Certificate.objects.issued().count(), 3)
        self.assertEqual(Certificate.objects.revoked().count(), 1)
        self.assertEqual(Certificate.objects.retired().count(), 1)

    def test_refresh_crls(self):
        pass

    #
    # Edge cases
    #

    def test_wrong_issuer(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor()
            ca, _ = self.issue_ca(anchor)

            entity = Entity.objects.create(issuer=ca, dn={'common_name': 'Entity'})

        with self.assertRaises(ValueError):
            anchor.issue_cert(entity, self.keys['entity'][0])

    def test_issue_authority_from_entity(self):
        pub, priv = self.keys['ca']

        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor()

            ca = Authority.objects.create(
                issuer=anchor, dn={'common_name': 'CA'},
                key_pem=self.private_key_pem(priv),
            )
            cert = anchor.issue_cert(Entity.objects.get(pk=ca.pk), pub)

            self.assertEqual(ca.current_certificate(), cert)

    def test_crl_wrong_issuer(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor()
            ca, _ = self.issue_ca(anchor)
            crl = self.new_crl(ca)

            with self.assertRaises(ValueError):
                anchor.refresh_crl(crl)

    def test_no_valid_cert(self):
        with Now(utcdatetime(2000, 1, 1)):
            anchor, _ = self.issue_anchor()
        with Now(utcdatetime(2115, 1, 1)):
            with self.assertRaises(NoValidCertificate):
                self.issue_ca(anchor)

    #
    # Utilities
    #

    def issue_anchor(self, dn=None, expires_at=timedelta(days=3650), **kwargs):
        pub, priv = self.keys['anchor']
        if dn is None:
            dn = {'common_name': 'Anchor'}

        anchor = Authority.objects.create(
            issuer=None, dn=dn, key_pem=self.private_key_pem(priv),
            **kwargs
        )
        cert = anchor.issue_cert(anchor, pub, expires_at=expires_at)

        return (anchor, cert)

    def issue_ca(self, anchor=None, name='CA', expires_at=timedelta(days=365), **kwargs):
        pub, priv = self.keys['ca']

        if anchor is None:
            anchor, _ = self.issue_anchor()

        ca = Authority.objects.create(
            issuer=anchor, dn={'common_name': name},
            key_pem=self.private_key_pem(priv),
            **kwargs
        )
        cert = anchor.issue_cert(ca, pub, expires_at=expires_at)

        return (ca, cert)

    def issue_entity(self, name, ca=None, expires_at=timedelta(days=90), emails=[], domains=[], **kwargs):
        pub, priv = self.keys['entity']

        if ca is None:
            ca, _ = self.issue_ca()

        entity = Entity.objects.create(issuer=ca, dn={'common_name': name}, **kwargs)
        cert = ca.issue_cert(entity, pub, expires_at=expires_at, emails=emails, domains=domains)

        return (entity, cert)

    def new_crl(self, ca=None, issuer=None):
        if ca is None:
            ca, _ = self.issue_ca(is_crl_signer=True)
        if issuer is None:
            issuer = ca

        crl = CRL.objects.create(authority=ca, issuer=issuer)

        return crl

    def private_key_pem(self, key):
        return pem.armor('RSA PRIVATE KEY', asymmetric.dump_private_key(key, None, 'der'))

    def public_key_pem(self, key):
        return pem.armor('PUBLIC KEY', asymmetric.dump_private_key(key, None, 'der'))

    keys = {
        'anchor': (
            asymmetric.load_public_key(b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwayat8fmHnKigH5a5osKmiyQn\nuC/v9b5BetEeIWWm3sWnfTdtSE1/PHcmB5RauJ+CIUJN3Pwzqk/mfV2ZFC3fPtLp\nfAcjggoVUnnGi8+F2fODn55BoOI7XgTVhMnpvuzHilrpWp4qfOxc1cqGyEcvEONG\nZrQbT0tqFURyrghYgwIDAQAB\n-----END PUBLIC KEY-----\n'),
            asymmetric.load_private_key(b'-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALBrJq3x+YecqKAf\nlrmiwqaLJCe4L+/1vkF60R4hZabexad9N21ITX88dyYHlFq4n4IhQk3c/DOqT+Z9\nXZkULd8+0ul8ByOCChVSecaLz4XZ84OfnkGg4jteBNWEyem+7MeKWulanip87FzV\nyobIRy8Q40ZmtBtPS2oVRHKuCFiDAgMBAAECgYBYRnWHSnIaunfiD4xi/R87KJqB\nyXcrMiLuLt9enUV5FzV91nkalLg6d24DOH2yW3ltKuk7ft0vmQP8CDUCeQduPhez\nwwpqrhhm7+gA8NyyLJ/dL2B20Zj1sCyTx4Zt98VUD2DJ/TDwghDZI73sDE0ni/eF\n/wUhD9GFVMapGPnJYQJBANbAmxBshv0152qmMKY0D4r1eZvbhcnARA/OWDHo4qs8\nEpBUvKXyJ6Fi60REIFRsKJw9p/YFn+8Jpqp9cQqbcbECQQDSTaseA2ib8YAdJ0na\nulA1yuJjBNSKL3AaWhZ2w5nWoAqR5NB8uRToAEvxsX50uHODGqeny3eNG9aGc54t\nlCZzAkEAqFYaNumbdujGGgdjoySz+k0pok6VtOwNbgZlg9n1tBxGwPRrW/lRr2QG\n32A3p3WQ78g03NjT4WBDUOk7rwDiQQJAYoezIVe1fkKSpJYQuyLJi7pngL71mVyK\naD5HAhO4kt7etOYAbD8GtX/WFQH03ljA/e7SGAJzG7CsPMgUlwQvUwJBAJdDxtfo\nBtEa9B1fIAvIV0TEsPnnnWzhmOE4QIO59XxH9naUPJzx2MgwWOaHeNyBCq2nupxi\nSK6A3eIqoZdsFtg=\n-----END PRIVATE KEY-----\n')
        ),
        'ca': (
            asymmetric.load_public_key(b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDstKms+Qvrcc9kG6545+5Tnd+\nT88u6yLO67Ll7lL0M/PYeFXDMly0NJOg5xHqntQx1XTmWZbSDebHt3mt3ofvktm3\nZ3P/5KfGi5ywTMWnUQJRydCoRxy0MpN5whfw8jyXuHx2DTNW1SQDX4p/RkGONbyo\n1n7NvTH0Tv02sI+mxQIDAQAB\n-----END PUBLIC KEY-----\n'),
            asymmetric.load_private_key(b'-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMOy0qaz5C+txz2Q\nbrnjn7lOd35Pzy7rIs7rsuXuUvQz89h4VcMyXLQ0k6DnEeqe1DHVdOZZltIN5se3\nea3eh++S2bdnc//kp8aLnLBMxadRAlHJ0KhHHLQyk3nCF/DyPJe4fHYNM1bVJANf\nin9GQY41vKjWfs29MfRO/Tawj6bFAgMBAAECgYBSvb+8xeBbnFDaIb//DlOQ6LEz\nEZFamAYekJ8SAkLGh1S5GJ/CKP/zHSux4yC7Hy4+Z67GWeifpUsG8/cZYTX9geKC\nzXHrwYPwS0i69D+ugomiOlwVQTS9fAnIj/t6c0m4zVy90ZKkrZ+iMRVBETe4QRNX\nVc7sEs0XcgEhA8MSoQJBAPaj1vVnQIgcexJs1DexWX54iOgZulu1NlPM50PrjM3d\n4o9XKApd/AvidDf6qNBDpJaLvBvNQ5lExAh8KpgvaQ0CQQDLIBNtEDgu+LjJI9QX\nRbTcj6KTzzsufN+QaxVWAvqBxfz7o6UJ0q6p1036FYEgVLnXG8hKLhvEG85AA1on\nzdaZAkA6J8W+1ZrMvVJztL+RZjsA7DDz8WUUzLTDq7P4OulXfXM3c0iYsTKGJt5a\neLsnaFu9t7MiJxNCZ4mFqqlsevldAkEAhCoguav+AoIPKcDINURDw+cpb2c9KKhT\nhtJGFarmeB3s14bI0bVltFjFAd2QIQs/yDjpf2q04kr9TiVgOdnysQJAFb04JWTt\nO4J0O79tioEkZZNjA8anlaimMMvkjqrjvSe92k29g2L9KyqtFd+qgIBx+JvptaXX\n4qqrCgbDkOzOqg==\n-----END PRIVATE KEY-----\n')
        ),
        'entity': (
            asymmetric.load_public_key(b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1YrBEZTwKbyouBPd1e2umyHSs\nytJBgB/dLc2+rKYFSs+jIXXYM8cVs8icRoKNZJ1bO5IOcoSWSMjhnq2LWku7rRsz\nJD74ORmYkm+HGC1bLflIMWyW/c32k6FtdBmmquohN9y0NUQz2uMo2fpCFt3/fRB5\nB2EylWG2E7UbhPuKgwIDAQAB\n-----END PUBLIC KEY-----\n'),
            asymmetric.load_private_key(b'-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALVisERlPApvKi4E\n93V7a6bIdKzK0kGAH90tzb6spgVKz6MhddgzxxWzyJxGgo1knVs7kg5yhJZIyOGe\nrYtaS7utGzMkPvg5GZiSb4cYLVst+UgxbJb9zfaToW10Gaaq6iE33LQ1RDPa4yjZ\n+kIW3f99EHkHYTKVYbYTtRuE+4qDAgMBAAECgYB9nHdnFhhLPYqfTe8026DEYmNy\nWg7bL2hhmlu2JQff+Fvso7phXBINtHBD0QyN8FSMnqdZ+/JXxNXgcSvLql9w0LbN\nSoq5/w1ZBooUolj+PWQJjIjNnN8COXrQIvYVQ0EXjJYX1621S5rjwkgoW10de52j\nVzFEZEdbKtzHJ/ZPOQJBAOV6XKEG+8BomMsdiVLZ/HMqyU304opuJXoIRIVytRm2\nfUV+/pQ5e1lATyDHe9tJtWZ1kGWTg658GS7VcTKIM9cCQQDKWWY6bpFLirc6vP45\nq+Emc2qvrGBSkJuSw7KzRC45gT1bVaWIMRmHc1lDQ7cXIHihctOfJK5VtWIJ2Sw/\n88k1AkEAkG4THsZmbRNoF27fn2XTniivyoD2lGn+7G+HsPYhRa216qejU2daWzI+\nm0LykXIy2enkmAngN1GkB/YO6N8QwQJAOVbJ9Cbev0RIlbl2ZMtC2s173tn+1Yaq\nvxT7b3cTjjIEO/xyEryvGkXidoAaws/tvvo143PWfu0OIfJLarffPQJBAMDr30OB\ncRfPT6oyF7bSCZr6tdnh2hmvo9EXn2kLWNeRkkIlNT/Wm6cTnBumKsQ6FQaN913p\nZEZUGJKdNF8c3+Y=\n-----END PRIVATE KEY-----\n')
        ),
    }

    def _handle_new_cert(self, instance=None, created=False, raw=False, **kwargs):
        if created and not raw:
            self.certs.append(instance)

    def _handle_new_crl(self, instance=None, created=False, raw=False, **kwargs):
        if created and not raw:
            self.crls.append(instance)
