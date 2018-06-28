from django.shortcuts import render
from django.template.loader import get_template
from django.http import HttpResponse
import datetime
import urllib.request
import requests
from xml.etree import ElementTree
import sys



# Create your views here.
file_opml = 'C:\\Users\\PRRAI\\Desktop\\rssfeed.opml'

def home(request):
    now = 'hello'
    words = {'hello', 'hi', 'there'}

    top_headings = []
    with open(file_opml, 'rt') as f:
        tree = ElementTree.parse(f)
    for node in tree.findall('body')[0]:
        top_heading = node.attrib.get('title')
        top_headings.append(top_heading)

    def find_sub_heading(index):
        sub_headings = []
        with open(file_opml, 'rt') as f:
            tree = ElementTree.parse(f)
            root = tree.getroot()
        for node in root.findall('body')[0][index]:
            sub_heading = node.attrib.get('title')
            sub_headings.append(sub_heading)
        return sub_headings


    return render(request, 'jobs\home.html', {'words': top_headings})




