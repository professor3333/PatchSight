from django.shortcuts import render


def post_detail(request, post):
    return render(request, "blog/post.html", {"post": post})
