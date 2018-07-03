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
            index = sub_heading.find('-')
            sub_heading = sub_heading[index + 2:]
            sub_headings.append(sub_heading)
            sub_headings.sort()
        return sub_headings

    def get_xml_urls(filename, index):
        urls=[]
        with open(filename, 'rt') as f:
            tree = ElementTree.parse(f)
            root = tree.getroot()
        for node in root.findall('body')[0][index]:
            url = node.attrib.get('htmlUrl')
            urls.append(url)
        return urls


    top_headings = get_top_headings(file_opml)


    objects = []
    for i in range(0, len(top_headings)):
        q=Job()
        q.top_heading=top_headings[i]
        sub_headings = get_sub_headings(file_opml, i)
        xml_urls = get_xml_urls(file_opml,i)
        unique_xml = []
        unique = []
        for j in range(0, len(sub_headings)):
            unique.append(sub_headings[j])
            unique_xml.append(xml_urls[j])
        q.sub_headings=zip(unique, unique_xml)
        #q.sub_headings = unique
        objects.append(q)
    objects.sort(key=lambda x:x.top_heading)



    return render(request, 'jobs\home.html', {'objects': objects})




