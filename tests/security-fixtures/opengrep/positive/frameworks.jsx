// Safe, non-operational syntax fixtures. These functions are never executed.
function expressExamples(req, res, childProcess, cors) {
  res.redirect(req.query.next);
  res.sendFile(req.query.path);
  cors();
  childProcess.exec(req.query.command);
  res.render(req.query.template, {});
}

function nextExamples(request, NextResponse, fs) {
  NextResponse.redirect(request.nextUrl.searchParams.get("next"));
  fs.readFile(request.nextUrl.searchParams.get("path"), () => {});
  return process.env.NEXT_PUBLIC_API_TOKEN;
}

function ReactExample(props) {
  return <div dangerouslySetInnerHTML={{__html: props.html}} />;
}
