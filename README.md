In this project every line of code could be changed with #Fixed lines in order to test it besides Vulnerability 5, which requires extra steps.

To check encryption:

pip install cryptography

open shell with:
python3 manage.py shell

>>> from cryptography.fernet import Fernet
---
>>>Fernet.generate_key()

It will give you a key that you need to insert inside settings.py ENCRYPTION_KEY

If you created notes before for it to work you will need to open shell and delete existing ones

python3 manage.py shell

>>>from mynotes.models import Note
---
>>>Note.objects.all().delete()

After that you website will work with note content encrypted 

