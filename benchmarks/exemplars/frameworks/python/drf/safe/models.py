from django.db import models


class Article(models.Model):
    title = models.CharField(max_length=200)
    body = models.TextField()
