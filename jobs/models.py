from django.db import models

class Job(models.Model):
    top_heading = models.CharField(max_length=100)
    sub_headings = []



