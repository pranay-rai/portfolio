from django.shortcuts import render
from django.template.loader import get_template
from django.http import HttpResponse
import datetime
import urllib.request
import requests
from xml.etree import ElementTree
from jobs.models import Job

import sys



# Create your views here.
file_opml = 'C:\\Users\\PRRAI\\Desktop\\rssfeed.opml'


def home(request):
    now = 'hello'
    words = {'hello', 'hi', 'there'}



    def get_top_headings(filename):
        top_headings = []
        with open(file_opml, 'rt') as f:
            tree = ElementTree.parse(f)
        for node in tree.findall('body')[0]:
            top_heading = node.attrib.get('title')
            top_headings.append(top_heading)
        return top_headings

    def get_sub_headings(filename, index):
        sub_headings = []
        with open(filename, 'rt') as f:
            tree = ElementTree.parse(f)
            root = tree.getroot()
        for node in root.findall('body')[0][index]:
            sub_heading = node.attrib.get('title')
            sub_headings.append(sub_heading)
        return sub_headings

    top_headings = get_top_headings(file_opml)


    objects = []
    for i in range(0, len(top_headings)):
        q=Job()
        q.top_heading=top_headings[i]
        sub_headings = get_sub_headings(file_opml, i)
        unique = []
        for j in range(0, len(sub_headings)):
            unique.append(sub_headings[j])
        q.sub_headings = unique
        objects.append(q)



    return render(request, 'jobs\home.html', {'objects': objects})




