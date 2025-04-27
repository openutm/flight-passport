from rolepermissions.decorators import has_permission_decorator, has_role_decorator


class HasRoleMixin:
    allowed_roles = []
    redirect_to_login = None

    def dispatch(self, request, *args, **kwargs):
        roles = self.allowed_roles
        return has_role_decorator(roles, redirect_to_login=self.redirect_to_login)(super().dispatch)(request, *args, **kwargs)


class HasPermissionsMixin:
    required_permission = ""
    redirect_to_login = None

    def dispatch(self, request, *args, **kwargs):
        permission = self.required_permission
        return has_permission_decorator(permission, redirect_to_login=self.redirect_to_login)(super().dispatch)(request, *args, **kwargs)
