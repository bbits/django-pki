from __future__ import absolute_import, division, print_function, unicode_literals

from base64 import b32encode
from datetime import timedelta
import logging
import operator
from os import urandom
import os.path
import random

from asn1crypto import pem, x509, keys
from asn1crypto.crl import CertificateList
from certbuilder import CertificateBuilder
from crlbuilder import CertificateListBuilder
from oscrypto import asymmetric

from django.core.files.base import ContentFile
from django.db import models, transaction
from django.db.models import Q
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.dispatch import Signal
from django.utils.encoding import force_text

from pki.lib.models import JSONCharField
from pki.lib.pki import public_from_private
from pki.lib.properties import lazy_property, cached_property
from pki.lib.timezone import now


logger = logging.getLogger(__name__)


class NoValidCertificate(Exception):
    """
    A valid certificate is required to perform an operation.

    This is generally raised when an authority has been asked to sign
    something, but it has no valid certificate with which to do so. It may
    indicate that certificates are not being renewed properly.

    """


class KeyDecryptionError(Exception):
    """ Error decrypting a private key. """


# Public signal advertising that a CRL has been regenerated. Clients might want
# to go get a fresh copy. Sender is the CRL instance.
crl_refreshed = Signal()


def random_serial():
    return random.SystemRandom().getrandbits(63)


def unique_id():
    return force_text(b32encode(urandom(10)))


#
# Entities
#

class EntityQuerySet(models.QuerySet):
    def role_client(self):
        return self.filter(role__in=[self.model.ROLE_CLIENT, self.model.ROLE_BOTH])

    def role_server(self):
        return self.filter(role__in=[self.model.ROLE_SERVER, self.model.ROLE_BOTH])


class Entity(models.Model):
    """
    A single entity in the PKI.

    It may be a CA or a leaf. It may have multiple certificates assocated with
    it, but only one will be considered current.

    """
    ROLE_NONE = 0
    ROLE_CLIENT = 1 << 0
    ROLE_SERVER = 1 << 1
    ROLE_BOTH = ROLE_CLIENT | ROLE_SERVER
    ROLES = [
        (ROLE_NONE, "None"),
        (ROLE_CLIENT, "Client"),
        (ROLE_SERVER, "Server"),
        (ROLE_BOTH, "Client/Server"),
    ]

    issuer = models.ForeignKey('Authority', null=True, blank=True, on_delete=models.CASCADE, help_text="Issuing authority, if any.")
    dn = JSONCharField(help_text="Distinguished name, as a dictionary (https://github.com/wbond/certbuilder/blob/master/docs/api.md#subject-attribute).")
    role = models.PositiveSmallIntegerField(choices=ROLES, default=ROLE_NONE)

    objects = EntityQuerySet.as_manager()

    class Meta:
        verbose_name_plural = "Entities"

    def __unicode__(self):
        """
        Some attempt at an accurate but readable short description.
        """
        if 'common_name' in self.dn:
            if 'dn_qualifier' in self.dn:
                value = "{0}/{1}".format(self.dn['common_name'], self.dn['dn_qualifier'])
            else:
                value = self.dn['common_name']
        elif 'organizational_unit_name' in self.dn:
            value = self.dn['organizational_unit_name']
        elif 'organization_name' in self.dn:
            value = self.dn['organization_name']
        else:
            value = x509.Name.build(self.dn).human_friendly

        return value

    def as_authority(self, required):
        """
        Returns the associated Authority, if any.

        If required is False, this will just return the Entity if it's not an
        Authority.

        """
        try:
            entity = self.authority
        except Authority.DoesNotExist:
            if required:
                raise
            else:
                entity = self

        return entity

    def get_issuer(self):
        issuer = self.issuer
        if issuer is None:
            issuer = self.as_authority(required=True)

        return issuer

    def chain(self):
        """ Generates a chain of Authority objects, including the anchor. """
        if self.is_ca():
            authority = self.as_authority(required=True)
        else:
            authority = self.issuer

        while authority is not None:
            yield authority
            authority = authority.issuer

    def current_certificate(self, required=False, pem=False):
        """ The entity's most recently issued valid certificate. """
        cert = self.certificate_set.valid_now().order_by('-valid_at').first()
        if required and (cert is None):
            raise NoValidCertificate("PKI Entity {0} has no valid certificate.".format(self))

        if (cert is not None) and pem:
            cert = cert.pem()

        return cert

    def intermediate_certificates(self):
        """ Returns a list of Certificates between us and our anchor. """
        return filter(None, [authority.current_certificate(required=False)
                             for authority in self.chain()
                             if authority.issuer_id is not None])

    def is_ca(self):
        return Authority.objects.filter(pk=self.pk).exists()

    def is_anchor(self):
        return (self.issuer_id is None)

    def is_client(self):
        return (self.role & self.ROLE_CLIENT) != 0

    def is_server(self):
        return (self.role & self.ROLE_SERVER) != 0

    #
    # Internal
    #

    def _key_usage(self, algo):
        """
        Returns an appropriate set of keyUsage values.

        The correct values are described by RFC 3279 and the OpenVPN man page
        (--remote-cert-tls).

        """
        ku = set()

        if self.is_client():
            ku.update(['digital_signature'])
        if self.is_server():
            ku.update(['digital_signature', 'key_encipherment' if (algo == 'rsa') else 'key_agreement'])

        return ku

    def _extended_key_usage(self):
        eku = set()

        if self.is_client():
            eku.add('client_auth')
        if self.is_server():
            eku.add('server_auth')

        return eku


class Authority(Entity):
    """
    An entity may also be a certificate authority.

    The unique_id field is primarily intended as an arbitrary identifier for
    URLs, filenames, etc. It can also be used to manually create well-known
    authorities. Programmatically generated authorities should probably use the
    random default.

    """
    unique_id = models.CharField(max_length=32, default=unique_id, db_index=True, unique=True)
    key_pem = models.TextField(help_text="PEM-encoded private key.")
    is_cert_signer = models.BooleanField(default=True, help_text="Does this authority sign certificates?")
    is_crl_signer = models.BooleanField(default=True, help_text="Does this authority sign CRLs?")

    class Meta:
        verbose_name_plural = "Authorities"

    def as_authority(self, required=True):
        return self

    def issue_cert(self, entity, public_key,
                   valid_at=None, expires_at=timedelta(days=90),
                   emails=[], domains=[], ips=[], password=None):
        """
        Issues a new certificate for a given child entity.

        entity: An Entity or Authority. The entity may be self for self-signed
            certs; otherwise, its issuer must be this authority.
        public_key: The entity's public key.
        valid_at: datetime or None. Defaults to now.
        expires_at: datetime or timedelta. Defaults to valid_at + 90 days.
        emails: List of emails for subjectAltName.
        domains: List of domains for subjectAltName.
        ips: List of IP addresses for subjectAltName.
        password: Private key password, if any.

        Returns the new Certificate.

        """
        if (entity.id != self.id) and (entity.issuer_id != self.id):
            raise ValueError("Entity is not a child of this Authority.")

        # Upgrade to the associated Authority, if it exists.
        entity = entity.as_authority(required=False)

        if valid_at is None:
            valid_at = now()

        if isinstance(expires_at, timedelta):
            expires_at = valid_at + expires_at

        with transaction.atomic():
            cert = Certificate.objects.reserve(entity, valid_at, expires_at)
            builder = self._certificate_builder(entity, public_key, emails, domains, ips, cert)
            asn_cert = builder.build(self.private_key(password))
            cert.issue(self, asn_cert)

        return cert

    def _certificate_builder(self, entity, public_key, emails, domains, ips, cert):
        builder = CertificateBuilder(entity.dn, public_key)
        builder.serial_number = cert.serial
        builder.begin_date = cert.valid_at
        builder.end_date = cert.expires_at
        builder.hash_algo = 'sha256'
        builder.ca = entity.is_ca()
        builder.key_usage = entity._key_usage(public_key.algorithm)
        builder.extended_key_usage = entity._extended_key_usage()
        builder.subject_alt_emails = emails
        builder.subject_alt_domains = domains
        builder.subject_alt_ips = ips
        builder.crl_url = self._crl_url(entity)

        if entity.id == self.id:
            builder.self_signed = True
        else:
            builder.issuer = self.current_certificate(required=True).asn_cert

        return builder

    def _crl_url(self, entity):
        """ Returns a value suitable for CertificateBuilder().crl_url. """
        crl_url = None

        try:
            authority = entity.get_issuer()
            crl = authority.crl

            crl_url = crl.url()
            if crl.is_indirect:
                crl_url = (crl_url, crl.issuer.current_certificate(required=True).asn_cert)
        except CRL.DoesNotExist:
            pass
        except NoValidCertificate:
            logger.error("Indirect CRL issuer has no valid certificate.")
            raise

        return crl_url

    def refresh_crl(self, crl):
        """
        Issues an updated CRL.

        This updates the timestamps and number of the given CRL and renders the
        new version. The caller is advised to use select_for_update() when
        loading the CRL to avoid race conditions.

        """
        if crl.issuer != self:
            raise ValueError("This is not the issuer for the given CRL.")

        # Catch-22: In order to render the CRL, we need the final URL, which we
        # only get after we write to the file and save the model. So the first
        # time around, we have to save a dummy file to bootstrap ourselves.
        if not crl.crl_file:
            crl.crl_file.save(crl.filename(), ContentFile(b''), save=True)

        crl.number += 1
        crl.this_update = now()
        crl.next_update = crl.this_update + timedelta(seconds=crl.ttl)
        crl.refresh_at = crl.refresh_target(crl.this_update, crl.next_update)

        issuer_cert = self.current_certificate(required=True)
        builder = CertificateListBuilder(crl.url(), issuer_cert.asn_cert, crl.number)
        builder.this_update = crl.this_update
        builder.next_update = crl.next_update

        # Handle indirect CRLs
        if crl.authority_id != crl.issuer_id:
            builder.certificate_issuer = crl.authority.current_certificate(required=True).asn_cert

        for cert in crl.revoked_certificate_set.iterator():
            builder.add_certificate(cert.serial, cert.revoked_at, 'privilege_withdrawn')

        asn_crl = builder.build(self.private_key())

        with crl.crl_file.storage.open(crl.crl_file.name, 'wb') as f:
            f.write(asn_crl.dump())

        crl.save()
        crl_refreshed.send_robust(crl)

        # Revoked certificates are required to make one final appearance in
        # their CRLs after they've expired. Then we can forget about them.
        crl.revoked_certificate_set.expired_as_of(builder.this_update).update(state=Certificate.RETIRED)

        return crl

    @property
    def issued_certificate_set(self):
        return Certificate.objects.filter(entity__issuer=self)

    def get_crl(self):
        try:
            crl = self.crl
        except CRL.DoesNotExist:
            crl = None

        return crl

    def is_ca(self):
        return True

    def _key_usage(self, algo):
        ku = set()

        if self.is_cert_signer:
            ku.add('key_cert_sign')
        if self.is_crl_signer:
            ku.add('crl_sign')

        ku |= super(Authority, self)._key_usage(algo)

        return ku

    def is_private_key_encrypted(self):
        try:
            self.private_key(password=None)
        except KeyDecryptionError:
            is_encrypted = True
        else:
            is_encrypted = False

        return is_encrypted

    def public_key_info(self, password=None):
        """ Returns the PublicKeyInfo for our public key. """
        return public_from_private(self.private_key_info(password))

    def private_key_info(self, password=None):
        """ Returns the PrivateKeyInfo for our private key. """
        private_key = self.private_key(password)
        der = asymmetric.dump_private_key(private_key, None, 'der')
        private_key_info = keys.PrivateKeyInfo.load(der)

        return private_key_info

    def private_key(self, password=None):
        """ Returns the oscrypto private key. """
        try:
            key = asymmetric.load_private_key(self.key_pem.encode('ascii'), password)
        except OSError as e:
            raise KeyDecryptionError(e)

        return key


#
# Certificates
#

class CertificateQuerySet(models.QuerySet):
    def reserve(self, entity, valid_at, expires_at):
        """ Creates a new Certificate to reserve the serial number. """
        return self.create(entity=entity, valid_at=valid_at, expires_at=expires_at)

    def valid_now(self):
        return self.valid_as_of(now())

    def valid_as_of(self, as_of):
        qs = [
            Q(state=self.model.ISSUED),
            Q(valid_at__lte=as_of),
            Q(expires_at__gt=as_of),
            Q(revoked_at__isnull=True) | Q(revoked_at__gt=as_of)
        ]

        return self.filter(reduce(operator.and_, qs))

    def issued(self):
        return self.filter(state=Certificate.ISSUED)

    def retired(self):
        return self.filter(state=Certificate.RETIRED)

    def revoked(self):
        return self.filter(revoked_at__isnull=False)

    def revokable(self):
        return self.filter(state=Certificate.ISSUED, revoked_at__isnull=True)

    def expired(self):
        return self.expired_as_of(now())

    def expired_as_of(self, as_of):
        return self.filter(expires_at__lte=as_of)

    def revoke(self, as_of=None):
        if as_of is None:
            as_of = now()

        return self.update(revoked_at=as_of)


def cert_upload_to(instance, filename):
    return os.path.join('pki/certs/', filename)


class Certificate(models.Model):
    """
    A single certificate for an entity.
    """
    RESERVED = 0    # Serial number has been reserved.
    ISSUED = 1      # Certificate has been issued.
    RETIRED = 2     # Certificate has expired and is no longer of interest.
    STATE_CHOICES = [
        (RESERVED, "Reserved"),
        (ISSUED, "Issued"),
        (RETIRED, "Retired"),
    ]

    # We'll just make these globally unique for simplicity.
    serial = models.BigIntegerField(primary_key=True, default=random_serial)

    entity = models.ForeignKey(Entity, on_delete=models.CASCADE)
    state = models.PositiveSmallIntegerField(choices=STATE_CHOICES, default=RESERVED)

    created_at = models.DateTimeField(default=now)
    valid_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)

    cert_file = models.FileField(upload_to=cert_upload_to)

    objects = CertificateQuerySet.as_manager()

    def issue(self, issuer, asn_cert):
        """
        Turns this into an issued certificate.
        """
        if self.state != self.RESERVED:
            logger.warning("Attempt to issue a certificate in state {0}".format(self.get_state_display()))
            return None

        filename = '{0}/{1:016x}.cer'.format(issuer.unique_id, self.serial)
        content = ContentFile(asn_cert.dump())

        self.state = Certificate.ISSUED
        self.cert_file.save(filename, content, save=True)

        return self

    def revoke(self, as_of=None):
        if as_of is None:
            as_of = now()

        if self.state == self.ISSUED:
            self.revoked_at = as_of
            self.save()

    def is_revoked(self):
        return (self.revoked_at is not None)
    is_revoked.boolean = True

    def public_key_info(self):
        return self.asn_cert.public_key

    class _SubjectAlt(object):
        """ Property descriptor for a subset of subjectAltName values. """
        def __init__(self, name):
            self.name = name

        def __get__(self, instance, owner):
            if instance.asn_cert.subject_alt_name_value is not None:
                values = [
                    name.native for name in instance.asn_cert.subject_alt_name_value
                    if name.name == self.name
                ]
            else:
                values = []

            return values

    subject_alt_emails = _SubjectAlt('rfc822_name')
    subject_alt_domains = _SubjectAlt('dns_name')
    subject_alt_ips = _SubjectAlt('ip_address')

    def pem(self):
        return pem.armor("CERTIFICATE", self.der)

    @cached_property
    def asn_cert(self):
        """ Returns the underlying x509.Certificate object. """
        return x509.Certificate.load(self.der)

    @lazy_property
    def der(self):
        with self.cert_file.storage.open(self.cert_file.name, 'rb') as f:
            der = f.read()

        return der


#
# Revocation lists
#

class CRLQuerySet(models.QuerySet):
    def refresh(self):
        """ Refresh a set of CRLs. """
        count = 0

        for crl_id in self.values_list('id', flat=True):
            try:
                with transaction.atomic():
                    crl = CRL.objects.select_for_update().get(id=crl_id)
                    crl.refresh()
                    count += 1
            except KeyDecryptionError:
                logger.exception("Can not issue a CRL with an encrypted private key.")

        return count


class CRL(models.Model):
    """
    A certificate revocation list.

    This supports both direct and indirect CRLs. The issuer private key must
    not be encrypted so that we can automatically issue regular updates.

    """
    authority = models.OneToOneField(
        Authority, related_name='crl', on_delete=models.CASCADE,
        help_text="Authority whose certificates this CRL lists."
    )
    issuer = models.ForeignKey(
        Authority, related_name='issued_crl_set', on_delete=models.CASCADE,
        help_text="Authority that issues/signs the CRL."
    )

    this_update = models.DateTimeField(null=True, blank=True)
    next_update = models.DateTimeField(null=True, blank=True)
    refresh_at = models.DateTimeField(default=now)
    ttl = models.IntegerField(default=3600, help_text="CRL lifetime in seconds.")

    number = models.BigIntegerField(default=0, help_text="Monotonic CRL number.")

    crl_file = models.FileField()

    objects = CRLQuerySet.as_manager()

    @property
    def is_indirect(self):
        return (self.issuer_id != self.authority_id)

    def refresh(self):
        return self.issuer.refresh_crl(self)

    @property
    def revoked_certificate_set(self):
        """ The set of revoked certificates in this list. """
        return Certificate.objects.filter(state=Certificate.ISSUED,
                                          revoked_at__isnull=False,
                                          entity__issuer=self.authority)

    @staticmethod
    def refresh_target(this_update, next_update):
        """
        Calculates a suitable refresh time.
        """
        delta = (next_update - this_update).total_seconds()
        target = this_update + timedelta(seconds=delta * 0.75)
        latest = next_update - timedelta(seconds=300)

        return max(min(target, latest), this_update)

    def url(self):
        """
        Returns the URL or expected URL of the CRL.

        If we haven't rendered the CRL for the first time, this will return the
        expected URL. In this case, the URL could change once it's rendered.
        This fallback really only exists to workaround the chicken-egg problem
        with anchors when bootstrapping PKIs from fixtures in test deployments
        (can't sign a CRL without the anchor cert, can't render the anchor cert
        without the CRL URL).

        """
        try:
            url = self.crl_file.url
        except ValueError:
            url = self.crl_file.storage.url(self.filename())

        return force_text(url)

    def filename(self):
        return '{0}.crl'.format(self.authority.unique_id)

    def pem(self):
        return pem.armor("X509 CRL", self.der)

    def asn_crl(self):
        """ Returns the underlying CertificateList object. """
        return CertificateList.load(self.der)

    @lazy_property
    def der(self):
        with self.crl_file.storage.open(self.crl_file.name, 'rb') as f:
            der = f.read()

        return der


@receiver(post_save, sender=CRL)
def render_initial_crl(sender, instance, created, raw, **kwargs):
    if created and (not raw):
        instance.refresh()


#
# SigningRequest
#

class SigningRequest(models.Model):
    """
    Our version of a certificate signing request.

    This does not hold an actual CSR, just the fields we need to issue a
    certificate for an entity. Clients of this app can create these for
    password-protected authorities so that the certificates can be approved by
    administrators.

    """
    created_at = models.DateTimeField(default=now)
    entity = models.ForeignKey('Entity', on_delete=models.CASCADE)
    key_pem = models.TextField(help_text="PEM-encoded public key.")
    days = models.IntegerField(default=365, help_text="Validity time in days.")
    emails = JSONCharField(default=[], blank=True, help_text="Subject alt emails (JSON).")
    domains = JSONCharField(default=[], blank=True, help_text="Subject alt domains (JSON).")
    ips = JSONCharField(default=[], blank=True, help_text="Subject alt IPs (JSON).")
    message = models.CharField(max_length=255, blank=True)

    def public_key(self):
        return asymmetric.load_public_key(self.key_pem.encode('ascii'))

    def issue(self, password=None):
        """
        Issue a certificate for this request.
        """
        issuer = self.entity.get_issuer()

        certificate = issuer.issue_cert(
            self.entity, self.public_key(),
            expires_at=timedelta(days=self.days),
            emails=self.emails, domains=self.domains, ips=self.ips,
            password=password
        )

        return certificate
