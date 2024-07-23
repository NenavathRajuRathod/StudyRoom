from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class Notes(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    title=models.CharField(max_length=700)
    description=models.TextField()
    
    def __str__(self):
        return  self.title
    



class HomeWork(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    subject=models.CharField(max_length=30)
    title=models.CharField(max_length=100)
    desc=models.TextField()
    due=models.DateField()
    status=models.BooleanField(default=False)
    def __str__(self):
        return  self.title
    

class ToDo(models.Model):
    user=models.ForeignKey(User,on_delete=models.CASCADE)
    title=models.CharField(max_length=100)
    status=models.BooleanField(default=False)
    def __str__(self):
        return  self.title


