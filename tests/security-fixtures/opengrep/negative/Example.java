class Example { Process synthetic(String value) throws Exception { return new ProcessBuilder("printf", value).start(); } }
