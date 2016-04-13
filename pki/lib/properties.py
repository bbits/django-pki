from __future__ import absolute_import, division, print_function, unicode_literals

import threading


class cached_property(object):
    """
    Decorator that creates a cached read/write property. This caches the return
    value of the getter function for reuse. You can also set the cached value
    manually. You can clear the cache by deleting the property; it will be
    recalculated and returned on the next access.

        class Author(models.Model):
            ...

            @cached_property
            def book_count(self):
                return self.book_set.count()


    author.book_count   # Executes query
    author.book_count   # Returns cached value
    del author.book_count   # Flushes the cached value
    author.book_count   # Executes query again

    If you want the property to be thread-safe:

        class Author(models.Model):
            ...

            @cached_property(thread_safe=True)
            def book_count(self):
                return self.book_set.count()


    >>> class C(object):
    ...    def __init__(self):
    ...        self.count = 0
    ...
    ...    @cached_property
    ...    def prop(self):
    ...        self.count += 1
    ...        return self.count
    >>> c = C()
    >>> c.prop
    1
    >>> c.prop
    1
    >>> del c.prop
    >>> del c.prop  # Should do nothing
    >>> c.prop
    2
    >>> c.prop = 10
    >>> c.prop
    10
    """
    __slots__ = ['lock', 'getter', 'cached_attr_name']

    def __init__(self, getter=None, thread_safe=False):
        if getter is not None:
            self._set_getter(getter)

        self.lock = threading.Lock() if thread_safe else DummyLock()

    def __call__(self, getter):
        self._set_getter(getter)

        return self

    def _set_getter(self, getter):
        self.getter = getter
        self.cached_attr_name = '_cached_property_' + getter.__name__

    def __get__(self, instance, owner):
        value = None

        with self.lock:
            if not hasattr(instance, self.cached_attr_name):
                value = self.getter(instance)
                setattr(instance, self.cached_attr_name, value)
            else:
                value = getattr(instance, self.cached_attr_name)

        return value

    def __set__(self, instance, value):
        with self.lock:
            setattr(instance, self.cached_attr_name, value)

    def __delete__(self, instance):
        with self.lock:
            if hasattr(instance, self.cached_attr_name):
                delattr(instance, self.cached_attr_name)


class lazy_property(object):
    """
    Read-once cached property.

    Much like cached_property above, but this actually replaces itself with the
    cached value. Once accessed, it becomes a normal attribute.

    """
    def __init__(self, getter):
        self.getter = getter

    def __get__(self, instance, owner):
        value = self.getter(instance)
        setattr(instance, self.getter.__name__, value)

        return value


class DummyLock(object):
    __slots__ = []

    def __enter__(self):
        pass

    def __exit__(self, *args, **kwargs):
        pass


class classproperty(object):
    """
    @property, meet @classmethod.
    """
    def __init__(self, getter):
        self.getter = getter

    def __get__(self, obj, cls=None):
        if cls is None:
            cls = type(obj)

        return self.getter(cls)


class staticproperty(object):
    """
    @property, meet @staticmethod.
    """
    def __init__(self, getter):
        self.getter = getter

    def __get__(self, obj, cls=None):
        return self.getter()
