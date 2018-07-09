from django.shortcuts import render

from django.http import HttpResponse

import urllib.request

import requests


from jobs.models import URLForm
import whois



def home(request):

    url = ""
    #if request.method == 'POST':
    #    form = URLForm(request.POST)

    #    if form.is_valid():
    #        url = URLForm.cleaned_data['url']
    #else:
    form = URLForm()

    return render(request, 'jobs\home.html', {'form':form})

def results(request):

    if request.method == "POST":
        dataForm = URLForm(request.POST)

        if dataForm.is_valid():
            url = dataForm.cleaned_data['url']
        else:
            dataForm = URLForm()

    #status = whois.whois(url)
    try:
        r=requests.head(url)
        status='Live'
    except requests.ConnectionError:
        status = 'Not Live'




    return render(request, 'jobs\\results.html', {'word':url, 'status':status})


