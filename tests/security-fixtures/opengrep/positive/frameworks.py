"""Safe, non-operational syntax fixtures. These functions are never executed."""

import os
import pickle
from django.shortcuts import redirect
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from flask import request, send_file
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware


def flask_examples(app):
    app.run(debug=True)
    send_file(request.args.get("path"))
    redirect(request.args.get("next"))
    os.system(request.args.get("command"))
    return pickle.loads(request.data)


@csrf_exempt
def django_examples(request, Model, sql):
    Model.objects.raw(sql + request.body)
    return mark_safe(request.body)


def fastapi_examples(app, request):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
    )
    FileResponse(request.query_params.get("path"))
    os.system(request.query_params.get("command"))
    return pickle.loads(request.body())
