import java.io.File;
import java.io.ObjectInputStream;

class FrameworkExamples {
    Object command(Object request) throws Exception {
        new ProcessBuilder(request.getParameter("command")).start();
        return null;
    }

    String redirect(Object request) {
        return "redirect:" + request.getParameter("next");
    }

    File file(Object request) {
        return new File(request.getParameter("path"));
    }

    Object deserialize(Object stream) throws Exception {
        return new ObjectInputStream(stream);
    }

    @CrossOrigin(origins = "*")
    void cors() {}

    Object query(Object entityManager, String sql, Object value) {
        return entityManager.createNativeQuery(sql + value);
    }

    void actuator(Object authorization) {
        authorization.requestMatchers("/actuator/**").permitAll();
    }
}
