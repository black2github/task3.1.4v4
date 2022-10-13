package ru.kata.spring.boot_security.demo;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.UserDetailsManager;
import ru.kata.spring.boot_security.demo.model.CustomUserSerializer;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.LinkedHashSet;

public class Main {
    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws JsonProcessingException {
        log.debug("createRole: <-");

        Role role1 = new Role("USER");
        Role role2 = new Role("ADMIN");

        User user = new User("user1@domen.com", "password_text", 1);
        user.setFirstName("firstName");
        user.setLastName("lastName");
        user.setRoles(new LinkedHashSet<Role>(Arrays.asList(role1, role2)));

        log.debug("user2="+user);
        log.debug("user.getRoles().contains(role1) = " + user.getRoles().contains(role1));
        role1.setId(1l);
        log.debug("user.getRoles().contains(role1) = " + user.getRoles().contains(role1));

        log.debug("array = " + user.getRoleNames().toArray(new String[0]));

        ObjectMapper objectMapper = new ObjectMapper();
        // SimpleModule module =
        //         new SimpleModule("CustomUserSerializer", new Version(1, 0, 0, null, null, null));
        // module.addSerializer(User.class, new CustomUserSerializer());
        // objectMapper.registerModule(module);

        ObjectWriter w = objectMapper.writer();
        String jUser = w.with(SerializationFeature.INDENT_OUTPUT).writeValueAsString(user);
        log.debug("jsonUser = " + jUser);

        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false);

        ObjectWriter objectWriter = objectMapper.writer().with(SerializationFeature.INDENT_OUTPUT);

        User user1 = objectMapper.readValue(jUser, User.class);

        log.debug("deserialized user = " +user1);
    }
}
