from __future__ import absolute_import, division, print_function, unicode_literals

import datetime
from decimal import Decimal
import json

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            value = unicode(obj)
        elif isinstance(obj, datetime.datetime):
            assert settings.TIME_ZONE == 'UTC'
            value = obj.strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            value = super(JSONEncoder, self).default(obj)

        return value


def dumps(value):
    return JSONEncoder().encode(value)


def loads(txt):
    return json.loads(txt,
                      parse_float=Decimal,
                      encoding=settings.DEFAULT_CHARSET)


class JSONDict(dict):
    """
    Hack so repr() called by dumpdata will output JSON instead of
    Python formatted data. This way fixtures will work!
    """
    def __repr__(self):
        return dumps(self)


class JSONList(list):
    """
    As above.
    """
    def __repr__(self):
        return dumps(self)


class JSONField(models.Field):
    """
    Defines a field that stores an encoded JSON object.
    """
    # Deprecated in 1.8, to be removed in 1.10. And yet still seems necessary
    # in practice if we want instance properties to always be decoded.
    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('default', '{}')

        super(JSONField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return 'TextField'

    def get_prep_value(self, value):
        if value is None:
            pass
        elif isinstance(value, basestring):
            pass
        elif isinstance(value, (dict, list)):
            value = dumps(value)
        else:
            raise ValidationError("JSON value must be a dict or list (found {0}).".format(type(value)))

        return value

    def from_db_value(self, value, expression, connection, context):
        return self.to_python(value)

    def to_python(self, value):
        """
        Converts our string value to JSON after we load it from the DB.
        """
        if isinstance(value, basestring):
            try:
                value = loads(value)
            except Exception:
                pass

        if isinstance(value, dict):
            value = JSONDict(**value)
        else:
            value = JSONList(value)

        return value

    def formfield(self, **kwargs):
        defaults = dict(
            {'max_length': self.max_length, 'widget': forms.Textarea},
            **kwargs
        )

        return super(JSONField, self).formfield(**defaults)


class JSONCharField(JSONField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 255)

        super(JSONCharField, self).__init__(*args, **kwargs)

    def get_internal_type(self):
        return 'CharField'

    def formfield(self, **kwargs):
        defaults = dict(
            {'max_length': self.max_length, 'widget': forms.TextInput},
            **kwargs
        )

        # Note: deliberately skipping a superclass.
        return super(JSONField, self).formfield(**defaults)
