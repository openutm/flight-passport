from allauth.account.forms import LoginForm, ResetPasswordForm, SignupForm


class PassportSignUpForm(SignupForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for fieldname, field in self.fields.items():
            input_type = field.widget.input_type
            if input_type not in ["checkbox"]:
                field.widget.attrs.update({"class": "form-input"})


class PassportLoginForm(LoginForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for fieldname, field in self.fields.items():
            input_type = field.widget.input_type
            if input_type not in ["checkbox"]:
                field.widget.attrs.update({"class": "form-input"})


class ResetPasswordForm(ResetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for fieldname, field in self.fields.items():
            input_type = field.widget.input_type
            if input_type not in ["checkbox"]:
                field.widget.attrs.update({"class": "form-input"})
