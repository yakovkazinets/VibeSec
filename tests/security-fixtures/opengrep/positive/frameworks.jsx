// Safe, non-operational syntax fixtures. These functions are never executed.
function expressExamples(req, res, childProcess, cors) {
  res.redirect(req.query);
  res.sendFile(req.path);
  cors();
  childProcess.exec(req.command);
  res.render(req.template, {});
}

function nextExamples(request, NextResponse, fs) {
  NextResponse.redirect(request.url);
  fs.readFile(request.path, () => {});
  return process.env.NEXT_PUBLIC_API_TOKEN;
}

function ReactExample(props) {
  return <div dangerouslySetInnerHTML={{__html: props.html}} />;
}
