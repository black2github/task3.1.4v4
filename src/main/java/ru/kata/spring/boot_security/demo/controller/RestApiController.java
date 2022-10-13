package ru.kata.spring.boot_security.demo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import ru.kata.spring.boot_security.demo.*;
import ru.kata.spring.boot_security.demo.configs.util.UserValidator;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

import javax.validation.Valid;
import java.util.List;

import static ru.kata.spring.boot_security.demo.configs.AppURLs.*;

//RestController // = @Controller + @ResponseBody
@Controller
@CrossOrigin
@RequestMapping(API_ADMIN) // "/api/admin"
public class RestApiController {
    private static final Logger log = LoggerFactory.getLogger(RestApiController.class);

    private final UserService userService;
    private UserValidator userValidator;

    @InitBinder
    protected void initBinder(WebDataBinder binder) {
        binder.setValidator(userValidator);
    }

    @Autowired
    public RestApiController(UserService userService) {
        this.userService = userService;
    }

    @Autowired
    public void setUserValidator(UserValidator userValidator) {
        this.userValidator = userValidator;
    }

    /**
     * GET / - получение списка всех пользователей
     */
    @GetMapping(USERS)
    //@PostAuthorize("returnObject.owner == authentication.name")
    // @PostFilter("hasRole('ADMIN') or filterObject.email == authentication.name") // admin или получать только по себе
    public ResponseEntity<List<User>> list() {
        log.debug("list: <- ");
        try {
            List<User> users = userService.listAll();
            log.debug("list: -> " + users);
            return new ResponseEntity<>(users, HttpStatus.OK);
        } catch (Exception ex) {
            riseError("list", ex);
            return null;
        }
    }

    // @GetMapping(USERS)
    // //@PostFilter("hasRole('ADMIN') or filterObject.email == authentication.name") // admin или получать только по себе
    // public List<User> list() {
    //     log.debug("list: <- ");
    //     try {
    //         List<User> users = userService.listAll();
    //         log.debug("list: -> " + users);
    //         return users;
    //     } catch (Exception ex) {
    //         riseError("list", ex);
    //         return null;
    //     }
    // }

    /**
     * GET users/:id - получение данных о конкретном пользователе
     */
    @GetMapping(USERS + "/{id}")
    // @PostFilter("hasRole('ADMIN') or filterObject.email == authentication.name") // admin или получать только по себе
    public ResponseEntity<User> getUserById(@PathVariable("id") long id) {
        log.debug("getUserById: <- id=" + id);
        try {
            User user = userService.find(id);
            log.debug("getUserById: -> " + user);
            return new ResponseEntity<User>(user, HttpStatus.OK);
        } catch (Exception ex) {
            riseError("getUserById", ex);
            return null;
        }
    }

    /**
     * POST /users - создание пользователя по данным из запроса
     */
    @PostMapping(USERS) // /user
    //@ResponseBody
    public ResponseEntity<User> createUser(@RequestBody @Valid User user, BindingResult bindingResult) {
        log.debug("createUser: <- " + user);
        try {
            if (bindingResult.hasErrors()) {
                List<ObjectError> errs = bindingResult.getAllErrors();
                throw new InvalidFormatApplicationException(errs.get(0).getDefaultMessage());
            }
            User u = userService.create(user);
            log.trace("createUser: -> " + u);
            return new ResponseEntity<User>(u, HttpStatus.OK);
        } catch (Exception e) {
            riseError("createUser", e);
            return null;
        }
    }

    /**
     * PATCH /user - обновление данных пользователя c id из объекта
     */
    // TODO убрать метод, оставить ...byId()
    @PatchMapping(USERS)
    //@ResponseBody
    public ResponseEntity<User> updateUser(@RequestBody @Valid User user, BindingResult bindingResult) {
        log.debug("updateUser: <- " + user);
        try {
            if (bindingResult.hasErrors()) {
                List<ObjectError> errs = bindingResult.getAllErrors();
                for (ObjectError error : errs) {
                    if (! "password".equals(error.getCode())) {
                        throw new InvalidFormatApplicationException(errs.get(0).getDefaultMessage());
                    }
                }
            }
            User usr = userService.update(user);
            log.debug("updateUser: -> " + usr);
            return new ResponseEntity<User>(usr, HttpStatus.OK);
        } catch (Exception ex) {
            riseError("updateUser", ex);
            return null;
        }
    }

    /**
     * PATCH /user - обновление данных пользователя из объекта
     */
    @PatchMapping(USERS+"/{id}")
    // вместе с настройкой '.antMatchers(API_USERS +"/**").authenticated()'
    @PreAuthorize("hasRole('ADMIN') or #id == principal.id")  // либо админ, либо обновляет данные по себе
    public ResponseEntity<User> updateUserById(@PathVariable("id") long id, @RequestBody @Valid User user, BindingResult bindingResult) {
        log.debug(String.format("updateUserById: <- id=%d, user=%s", id, user));
        try {
            if (bindingResult.hasErrors()) {
                List<ObjectError> errs = bindingResult.getAllErrors();
                for (ObjectError error : errs) {
                    if (! "password".equals(error.getCode())) {
                        throw new InvalidFormatApplicationException(errs.get(0).getDefaultMessage());
                    }
                }
            }
            user.setId(id);
            User usr = userService.update(user);
            log.debug("updateUserById: -> " + usr);
            return new ResponseEntity<User>(usr, HttpStatus.OK);
        } catch (Exception ex) {
            riseError("updateUserById", ex);
            return null;
        }
    }


    /**
     * DELETE /user - удаление пользователя c id
     */
    @DeleteMapping(USERS)
    @PreAuthorize("hasRole('ADMIN')")
    //@ResponseBody
    public ResponseEntity<?> deleteUser(@RequestParam(value = "id") Long id) {
        log.debug(String.format("deleteUser: <- id=%d", id));
        try {
            userService.delete(id);
            log.debug("deleteUser: -> .");
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception ex) {
            riseError("deleteUser", ex);
        }
        return null;
    }

    /**
     * DELETE /user - удаление пользователя c id
     */
    @DeleteMapping(USERS + "/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUserById(@PathVariable("id") long id) {
        log.debug(String.format("deleteUserById: <- id=%d", id));
        try {
            userService.delete(id);
            log.debug("deleteUserById: -> .");
            return new ResponseEntity<>(HttpStatus.OK);
        } catch (NotFoundApplicationException ex) {
            log.debug("deleteUserById: " + ex.getMessage());
            return new ResponseEntity<>(HttpStatus.GONE);
        } catch (Exception ex) {
            riseError("deleteUserById", ex);
        }
        return null;
    }

    /*
     * Формирование ResponseStatusException для передачи клиенту расширенной информации об ошибке.
     * Требует установки в application.properties настройки server.error.include-message=always
     */
    private void riseError(String methodName, Exception e) {
        log.warn(methodName + ": error -> " + e.getMessage());
        if ( e instanceof SecurityApplicationException) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage());
        } else if (e instanceof NotFoundApplicationException) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        } else if (e instanceof DataIntegrityViolationException
            || e instanceof ApplicationException) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        } else if (e instanceof JsonProcessingException) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, e.getMessage());
        } else {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
}

