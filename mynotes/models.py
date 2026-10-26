from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Note(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=200)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    #Vulnerability 5: A02:2021 - Cryptographic Failures
    
    #In this case sensetive data is stored in a clear text, which allows in case of 
    #sql-injection or if someone got access to database to see user sensitive information
    #such as passwords, personal info and etc. 
    
    #Fix could be an encryption of that information that later can be shown decrypted only to user.
    #In this case I did a basic clear-text prevention using django signing function in views, function for 
    #note view and detail. 
    

    def __str__(self):
        return self.title
