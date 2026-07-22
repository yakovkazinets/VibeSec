// Reviewed safe alternatives; these functions are never executed.
function expressExamples(res, childProcess, cors) {
  res.redirect("/home");
  res.sendFile("public/help.html", {root: "/srv/app"});
  cors({origin: "https://example.invalid"});
  childProcess.execFile("/usr/bin/printf", ["fixture"]);
  res.render("profile", {name: "fixture"});
}

function nextExamples(NextResponse, fs) {
  NextResponse.redirect(new URL("/home", "https://example.invalid"));
  fs.readFile("/srv/app/public/help.txt", () => {});
  return process.env.SERVER_ONLY_TOKEN;
}

function ReactExample(props) {
  return <div>{props.text}</div>;
}
