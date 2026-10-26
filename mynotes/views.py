from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.decorators.http import require_POST
from django import db
from django.db import connection 
from django.core import signing

from .forms import NoteForm
from .models import Note
import logging


def home(request):
    return render(request, "home.html")


def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        #Vulnerability 1: A07:2021 - Identification and Authentication Failures
        #CWE-521: Weak Password Requirements
        
        #In this case password requirements are missing completely.
        #User can make any password like 123 or qwerty, which are easy to brute force. 
        #Flawed code:
        password1 = request.POST.get("password1", "")
        password2 = request.POST.get("password2", "")
        #Fix could be for example either adding requirements to the password,
        # use of django available tools like UserCreationForm, or validate password with djangos validate_password
        
        #Fixed code could look like this extra lines:
        #if len(password1) <= 8 or password.isalnum() == True:
            #return render(request, "register.html", {"error": "weak password"})
        #For example we could also implement django validators 
        
        if password1 != password2:
            return render(request, "register.html", {"error": "Passwords do not match"})
        
        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "Username already exists."})
        
        user = User.objects.create_user(username=username, password=password1)
        return redirect("login")
        

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect("notes")
    #Vulnerability 2: A09:2021 - Security Logging and Monitoring Failures
    #CWE-778: Insufficient Logging
    
    #There is nothing that can show fails on logging, so for example if someone is trying
    #to brute force an account, nothing tells you that.
    
    #Fix: using python function logging we can get a notification in console lag that someone
    #for example failed to log in into account, if it happens a lot and from the same ip
    #we can assume that it might be an attempt to force their way into someone else's account
    #That of course is not enough and we also need to collect all information such as ip somewhere
    #to analyze information, but this could be used as a min requirment.
        #else:
            #logger = logging.getLogger("security")
            #logger.warning("LOGIN FAIL user=%s ip=%s", username, request.META.get("REMOTE_ADDR"))

    return render(request, "login.html")


@login_required
def notes_view(request):
    if request.method == "POST":
        form = NoteForm(request.POST)

        if form.is_valid():
            note = form.save(commit=False)
            note.owner = request.user
            #Vulnerability 5
            #Fix: protect note content using django in built function so that they are not stored in plain text
            #note.content = signing.dumps(note.content)
            note.save()
            return redirect("notes")
    else:
        form = NoteForm()

    notes = Note.objects.filter(owner=request.user).order_by("-created_at")
    
    #Vulnerability 5
    #Decode notes to an owner, try and exception added due to database already existing 
    # invalid to function formatted lines that it cant load, you probably wont need it on fresh start. 
    #for n in notes:
        #try:
            #n.content = signing.loads(n.content)
        #except signing.BadSignature:
            #pass

    return render(request, "notes.html", {"notes": notes, "form": form})

def note_detail(request, note_id):
    # Vulnerability 3: A01:2021 - Broken Access Control
    # CWE-862: Missing Authorization
    
    # The application does not check whether the user has permission
    # to access the requested note. Each note should belong to a
    # specific user, and users should only access their own notes.
    # Flaw in a code:
    note = get_object_or_404(Note, id=note_id)

    # Fix: Add an owner condition to the database query to ensure
    # that the note belongs to the currently logged-in user.

    # Fixed code:
    #note = get_object_or_404(Note, id=note_id, owner=request.user)
    
    #Vulnerability 5
    #Fix to clean text note content
    #try:
        #note.content = signing.loads(note.content)
    #except signing.BadSignature:
        #pass
    
    return render(request, "note_detail.html", {"note": note})

@login_required
def search_view(request):
    q = request.GET.get('q')
    
    cursor = db.connection.cursor()
    #Vulnerability 4: A03 - Injection 
    # CWE-89: SQL injection
    
    #There is an unsafe query that takes user input for a search,
    #which makes possible for any user to obtain others information with SQL-injection
    
    #Flawed code
    cursor.execute(
        f"SELECT n.id, n.title, n.content, u.username from mynotes_note n "
        f"JOIN auth_user u ON n.owner_id = u.id "
        f"WHERE n.owner_id = {request.user.id} AND n.title LIKE '%{q}%'"
        
    )
    #Fix: Usage of params, which are list or dict of parameters, using %s as a placeholder in the query string
    #for a list, so that after they will be replaced with params arguments in this case [request.user.id, f"%{q}%"]
    #With this user can't insert anything into sql query
    
    #Fixed last line of flawed code and removed fs since we don't need {}:
    #cursor.execute(
    #"SELECT n.id, n.title, n.content, u.username from mynotes_note n "
    #"JOIN auth_user u ON n.owner_id = u.id "
    #"WHERE n.owner_id = %s AND n.title LIKE %s", [request.user.id, f"%{q}%"]
    #)
    rows = cursor.fetchall()
    
    return render(request, "search.html", {"rows":rows, "q":q})

@require_POST
def logout_view(request):
    logout(request)
    return redirect("home")


