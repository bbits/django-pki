"""
Timezone utilities.

This wraps django.utils.timezone in a way that allows us to patch now() in a
standard way. It also has a few utilities of our own.

"""
from __future__ import absolute_import, division, print_function, unicode_literals

from django.utils.timezone import *  # noqa


def utcdatetime(*args, **kwargs):
    """
    Timezone-aware wrapper for the datetime constructor.

    If settings.USE_TZ is True, this will force tzinfo to utc. We should pretty
    much always use this to create simple datetime objects.

    """
    from datetime import datetime
    from django.conf import settings

    if settings.USE_TZ:
        kwargs.update(tzinfo=utc)

    return datetime(*args, **kwargs)


def utcfromtimestamp(timestamp):
    from datetime import datetime

    return datetime.fromtimestamp(timestamp, utc)


def totimestamp(datetime):
    from calendar import timegm

    return int(timegm(datetime.utctimetuple()))


def today():
    return now().date()


def now():
    """ Public API: import this. """
    return _now()


def _now():
    """ Private API: patch this. """
    import django.utils.timezone

    return django.utils.timezone.now().replace(microsecond=0)


def Now(dt):
    """ A context processor that sets the current datetime. """
    from datetime import date, time, datetime
    from mock import patch

    if isinstance(dt, date) and not isinstance(dt, datetime):
        dt = datetime.combine(dt, time(0, tzinfo=utc))

    return patch('{}._now'.format(__name__), lambda: dt)
