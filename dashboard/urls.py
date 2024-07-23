from django.urls import path
from . import views

urlpatterns = [
    path('',views.home),
    path('notes/',views.notes),
    path('deletenotes/<int:pk>/',views.deletenotes ,name='deletenotes'),
    path('notes_detail/<int:id>/',views.notes_detail ,name='notes_detail'),
    path('homework/',views.homework,name='homework'),
    path('updatehomework/<int:id>/',views.updatehomework,name='updatehomework'),
    path('updatetodo/<int:id>/',views.updatetodo,name='updatetodo'),
    path('deletetodo/<int:id>/',views.deletetodo,name='deletetodo'),
    path('deletehomework/<int:id>/',views.deletehomework,name='deletehomework'),
    path('youtube/',views.youtube,name='youtube'),
    path('todo/',views.todo,name='todo'),
    path('books/',views.books,name='books'),
    path('dict/',views.dict,name='dict'),
    path('profile/',views.profile,name='profile'),
    path('mockinterview/',views.mockInterview,name='mockinterview'),
    path('dsa/',views.dsa,name='dsa'),
    path('csfundamentals/',views.csfundamentals,name='csfundamentals'),
    
]
