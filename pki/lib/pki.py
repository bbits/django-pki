from __future__ import absolute_import, division, print_function, unicode_literals

from collections import OrderedDict

from asn1crypto import keys
from oscrypto import asymmetric
from oscrypto.errors import SignatureError


def verify_csr(csr):
    """
    Verifies the signature on a CertificationRequest.

    Returns True or False. May raise a ValueError if the key algorithm is unknown.

    """
    signature_algo = csr['signature_algorithm'].signature_algo
    hash_algo = csr['signature_algorithm'].hash_algo

    if signature_algo == 'rsassa_pkcs1v15':
        verify_func = asymmetric.rsa_pkcs1v15_verify
    elif signature_algo == 'dsa':
        verify_func = asymmetric.dsa_verify
    elif signature_algo == 'ecdsa':
        verify_func = asymmetric.ecdsa_verify
    else:
        raise ValueError("Unable to verify the CertificateList since the signature uses the unsupported algorithm %s", signature_algo)

    try:
        key_object = asymmetric.load_public_key(csr['certification_request_info']['subject_pk_info'])
        verify_func(
            key_object,
            csr['signature'].native,
            csr['certification_request_info'].dump(),
            hash_algo
        )
    except (SignatureError):
        valid = False
    else:
        valid = True

    return valid


def public_from_private(private_key_info):
    """
    Dervices a PublicKeyInfo from a PrivateKeyInfo.

    Until this API appears in asn1crypto.

    """
    return keys.PublicKeyInfo({
        'algorithm': keys.PublicKeyAlgorithm({
            'algorithm': keys.PublicKeyAlgorithmId(private_key_info.algorithm),
            'parameters': private_key_info['private_key_algorithm']['parameters']
        }),
        'public_key': private_key_info.public_key
    })


class PkiSlice(object):
    """
    A utility for extracting subsets of the PKI.

    Use this to walk certificate chains and gather up collections of PKI
    objects that are of interest to a particular client. The constructor takes
    a list of Entity objects to construct the primary chain(s).

    Additional chains can be added to gather up ancillary objects of interest.
    Primary chains populate the intermediates; non-primary chains only populate
    the extras.

    """
    def __init__(self, *entities):
        self._anchors = set()
        self._intermediates = OrderedDict()  # Used as an ordered set.
        self._extras = set()
        self._crls = set()

        for entity in entities:
            self.add_chain(entity, is_primary=True)

    def add_chain(self, entity, is_primary=False):
        """ Adds an arbitrary Authority to the mix. """
        for ca in entity.chain():
            if ca.is_anchor():
                self._anchors.add(ca)
            else:
                self._extras.add(ca)
                if is_primary:
                    self._intermediates[ca] = True

            crl = ca.get_crl()
            if (crl is not None) and (crl not in self._crls):
                self._crls.add(crl)
                if crl.is_indirect and not self._have_seen(crl.issuer):
                    self.add_chain(crl.issuer)

    def anchors(self, pem=False):
        """ The set of anchor Authorities. """
        if pem:
            anchors = list(self._entity_pems(self._anchors))
        else:
            anchors = list(self._anchors)

        return anchors

    def intermediates(self, pem=False):
        """ The ordered list of intermediates from the entity. """
        if pem:
            intermediates = list(self._entity_pems(self._intermediates.keys()))
        else:
            intermediates = list(self._intermediates.keys())

        return intermediates

    def extras(self, pem=False):
        """ The full set of non-anchor Authorities. """
        if pem:
            extras = list(self._entity_pems(self._extras))
        else:
            extras = list(self._extras)

        return extras

    def crls(self, pem=False):
        """ The set of CRLs for all Authorities. """
        if pem:
            crls = list(crl.pem() for crl in self._crls)
        else:
            crls = list(self._crls)

        return crls

    #
    # Internal
    #

    def _have_seen(self, authority):
        if authority.is_anchor():
            seen = authority in self._anchors
        else:
            seen = authority in self._extras

        return seen

    def _entity_pems(self, entities):
        """
        Generates PEM-encoded certificates for an iterable of Entity objects.

        Entities with no current certificate are skipped.

        """
        return filter(None, (entity.current_certificate(pem=True) for entity in entities))
