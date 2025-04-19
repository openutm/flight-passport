import django
from packaging.version import Version

__version__ = "2.2.1"


try:
    dj_version = Version(django.get_version())
except:
    dj_version = Version("1.10")


if dj_version < Version("1.7"):
    from rolepermissions.loader import load_roles_and_permissions

    load_roles_and_permissions()
else:
    default_app_config = "rolepermissions.apps.RolePermissions"
