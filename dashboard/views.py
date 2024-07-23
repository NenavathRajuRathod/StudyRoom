from django.shortcuts import render,redirect
from dashboard.models import Notes,HomeWork,ToDo
from django.contrib import messages
from youtubesearchpython import VideosSearch
import requests
import wikipedia
def home(request):
    return render(request,'home.html')



def notes(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method=='POST':
        title=request.POST.get('title')
        desc=request.POST.get('desc')
        notes=Notes(user=request.user,title=title,description=desc)
        notes.save()
        messages.success(request,"Notes added successfully")
    notes=Notes.objects.filter(user=request.user)
    context={
        'notes':notes,
    }
    return render(request,'notes.html',context)


def deletenotes(request,pk):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    Notes.objects.get(id=pk).delete()
    return redirect('/notes/')

def notes_detail(request,id):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    notes=Notes.objects.get(pk=id)
    return render(request,'notes_detail.html',{'notes':notes})



def homework(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method=='POST':
        subject=request.POST.get('subject')
        title=request.POST.get('title')
        desc=request.POST.get('desc')
        due=request.POST.get('due')
        status=False
        work=HomeWork(user=request.user,subject=subject,title=title,desc=desc,due=due,status=status)
        work.save()
    homework=HomeWork.objects.filter(user=request.user)
    if(len(homework)==0):
        homework_done=True
    else:
        homework_done=False
    return render(request,'homework.html',{'homework':homework,'homework_done':homework_done})


def updatehomework(request, id):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    homework = HomeWork.objects.get(id=id)
    homework.status = not homework.status  
    homework.save() 
    return redirect('/homework/')


def deletehomework(request, id):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    homework = HomeWork.objects.get(id=id)
    homework.delete()
    return redirect('/homework/')

def youtube(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method=='POST':
        search=request.POST.get('search')
        video=VideosSearch(search,limit=10)
        result_list=[]
        for i in video.result()['result']:
            result_dict={
                'input':search,
                'title':i['title'],
                'duration':i['duration'],
                'tumbnail':i['thumbnails'][0]['url'],
                'channel':i['channel']['name'],
                'link':i['link'],
                'views':i['viewCount']['short'],
                'published':i['publishedTime'],
                
            }
            desc=''
            if i['descriptionSnippet']:
                for j in i['descriptionSnippet']:
                    desc+=j['text']
            result_dict['descriptionSnippet']=desc
            result_list.append(result_dict)
        return render(request,'youtube.html',{'results':result_list})
    return render(request,'youtube.html')


def todo(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method=='POST':
        title=request.POST.get('title')
        todo=ToDo(user=request.user,title=title)
        todo.save()
    todos = ToDo.objects.filter(user=request.user)
    if (len(todos)==0):
        empty=True
    else:
        empty=False
    return render(request,'todo.html',{'todos':todos,'empty':empty})


def updatetodo(request,id):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    todo=ToDo.objects.get(id=id)
    todo.status=not todo.status
    todo.save()
    return redirect('/todo/')

def deletetodo(request,id):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    ToDo.objects.filter(id=id).delete()
    return redirect('/todo/')


def books(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method == 'POST':
        search = request.POST.get('search')
        url = "https://www.googleapis.com/books/v1/volumes?q=" + search
        r = requests.get(url)
        answer = r.json()
        result_list = []
        for item in answer.get('items', [])[:10]:
            volume_info = item.get('volumeInfo', {})
            thumbnail = volume_info.get('imageLinks', {}).get('thumbnail', '')
            preview = volume_info.get('previewLink', '')
            result_dict = {
                'title': volume_info.get('title', ''),
                'subtitle': volume_info.get('subtitle', ''),
                'description': volume_info.get('description', ''),
                'count': volume_info.get('pageCount', ''),
                'categories': volume_info.get('categories', []),
                'rating': volume_info.get('averageRating', ''),
                'thumbnail': thumbnail,
                'preview': preview,
            }
            result_list.append(result_dict)
        return render(request, 'books.html', {'results': result_list})
    return render(request, 'books.html')


def dict(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    if request.method == 'POST':
        text = request.POST.get('search')
        url = "https://api.dictionaryapi.dev/api/v2/entries/en_US/" + text
        r = requests.get(url)
        
        if r.status_code == 200:
            answer = r.json()
            try:
                phonetics = answer[0]['phonetics'][0]['text']
                audio = answer[0]['phonetics'][0]['audio']
                definition = answer[0]['meanings'][0]['definitions'][0]['definition']
                example = answer[0]['meanings'][0]['definitions'][0]['example']
                synonyms = answer[0]['meanings'][0]['definitions'][0].get('synonyms', [])
                context = {
                    'input': text,
                    'phonetics': phonetics,
                    'audio': audio,
                    'definition': definition,
                    'example': example,
                    'synonyms': synonyms
                }
            except (KeyError, IndexError):
                context = {'input': text}
        else:
            context = {'input': ''}

        return render(request, 'dictionary.html', context)
    return render(request, 'dictionary.html')


def profile(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    
    homework=HomeWork.objects.filter(user=request.user,status=False)
    todo=ToDo.objects.filter(user=request.user,status=False)
    if (len(homework)==0):
        homework_done=True
    else:
        homework_done=False
    if (len(todo)==0):
        todo_done=True
    else:
        todo_done=False

   
   
    return render(request,'profile.html',{'homework':homework,'todos':todo,'homework_done':homework_done,'todo_done':todo_done})



def mockInterview(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    return render(request,'mockinterview.html')


def dsa(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    return render(request,'dsa.html')


def csfundamentals(request):
    if not request.user.is_authenticated:
        return redirect('/auth/login/')
    return render(request,'csfundamentals.html')


