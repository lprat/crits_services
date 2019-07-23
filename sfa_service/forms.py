import os
from django import forms

class SFAConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    sfa_api = forms.CharField(required=True,
                               label="SFA API URI",
                               widget=forms.TextInput(),
                               initial='https://localhost:8000/',
                               help_text="SFA API URI.")
    key_api = forms.CharField(required=True,
                               label="SFA API KEY",
                               widget=forms.TextInput(),
                               initial='myapikey',
                               help_text="SFA API KEY.")
    tlp_value = forms.CharField(required=True,
                               label="Tlp value",
                               initial='red',
                               widget=forms.TextInput(),
                               help_text="Indicate TLP value.")
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(SFAConfigForm, self).__init__(*args, **kwargs)

class SFARunForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    import_file_ioc = forms.BooleanField(required=False,
                                    initial=False,
                                    label="Import",
                                    help_text="Import extracted file contains IOC informations in CRITS as sample.")
    import_file_yara = forms.BooleanField(required=False,
                                    initial=True,
                                    label="Import",
                                    help_text="Import extracted file matched by yara rules in CRITS as sample.")
    import_yara_score = forms.CharField(required=False,
                                    initial="7",
                                    label="Import",
                                    help_text="Import extracted file matched by yara rules in CRITS as sample, if score yara >.")
#    import_file = forms.BooleanField(required=False,
#                                    initial=False,
#                                    label="Import",
#                                    help_text="Import ALL extracted file in CRITS as sample.")
    debug_log = forms.BooleanField(required=False,
                                    initial=False,
                                    label="Debug",
                                    help_text="Insert debug info in log.")
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(SFARunForm, self).__init__(*args, **kwargs)

