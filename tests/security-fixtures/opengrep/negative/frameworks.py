"""Reviewed safe alternatives; these functions are never executed."""

import json
import subprocess
from django.shortcuts import redirect
from django.utils.html import escape
from flask import send_file
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware


def flask_examples(app):
    app.run(debug=False)
    send_file("help.txt")
    redirect("/home")
    subprocess.run(["/usr/bin/printf", "fixture"], check=True)
    return json.loads("{}")


def django_examples(request, Model):
    Model.objects.raw("SELECT id FROM fixture WHERE id = %s", [request.POST["id"]])
    return escape(request.body)


def fastapi_examples(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://example.invalid"],
        allow_credentials=True,
    )
    return FileResponse("/srv/app/public/help.txt")
