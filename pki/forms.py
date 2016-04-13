from django import forms


class RenewEntityForm(forms.Form):
    days = forms.IntegerField(initial=365)


class ApproveRequestForm(forms.Form):
    password = forms.CharField(required=False, widget=forms.PasswordInput)
