import java.io.File;

class FrameworkExamples {
    Object command() throws Exception {
        return new ProcessBuilder("/usr/bin/printf", "fixture").start();
    }

    String redirect() {
        return "redirect:/home";
    }

    File file() {
        return new File("/srv/app/public/help.txt");
    }

    @CrossOrigin(origins = "https://example.invalid")
    void cors() {}

    Object query(Object entityManager, Object value) {
        return entityManager.createNativeQuery("SELECT id FROM fixture WHERE id = :id").setParameter("id", value);
    }

    void actuator(Object authorization) {
        authorization.requestMatchers("/actuator/health").permitAll();
    }
}
