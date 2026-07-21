const parsed = JSON.parse(request.body.document);
dispatch(parsed.action);
