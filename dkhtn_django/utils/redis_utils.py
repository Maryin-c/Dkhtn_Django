from django_redis import get_redis_connection
from django.conf import settings

redis_clis = [get_redis_connection(str(i)) for i in range(16)]


def redis_get(db_index, key):
    return redis_clis[db_index].get(key)


def redis_set(db_index, key, value, timeout=settings.REDIS_TIMEOUT):
    redis_clis[db_index].set(key, value, timeout)


def redis_delete(db_index, key):
    redis_clis[db_index].delete(key)
