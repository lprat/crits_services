from django import forms

class WebSnortConfigForm(forms.Form):
    error_css_class = 'error'
    required_css_class = 'required'
    ws_query_url = forms.CharField(required=True,
                                   label="Websnort API",
                                   widget=forms.TextInput(),
                                   initial='https://localhost:8080/api/submit')

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('label_suffix', ':')
        super(WebSnortConfigForm, self).__init__(*args, **kwargs)
