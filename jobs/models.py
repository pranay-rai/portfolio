from django.db import models
from django import forms

class Job(models.Model):
    top_heading = models.CharField(max_length=100)
    sub_headings = []


class URLForm(forms.Form):
    url = forms.CharField(label = 'Enter URL  ', max_length=100)


