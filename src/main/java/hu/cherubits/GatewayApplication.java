package hu.cherubits;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.session.web.http.HeaderHttpSessionStrategy;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
@Controller
@EnableZuulProxy
public class GatewayApplication {

    private static final Logger LOG = Logger.getLogger(GatewayApplication.class.getName());

//    @CrossOrigin(origins = "*", maxAge = 3600)
    @CrossOrigin(origins = "*", maxAge = 3600, allowedHeaders = {"x-auth-token", "x-requested-with"})
    @RequestMapping("/user")
    @ResponseBody
    public Map<String, Object> user(Principal user) {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        map.put("name", user.getName());
        map.put("roles", AuthorityUtils.authorityListToSet(((Authentication) user)
                .getAuthorities()));
        
        return map;
    }

    @CrossOrigin(origins = "*", maxAge = 3600, allowedHeaders = {"x-auth-token", "x-requested-with"})
    @RequestMapping("/login")
    public String login() {
        return "forward:/";
    }
    
    @CrossOrigin(origins = "*", maxAge = 3600, allowedHeaders = {"x-auth-token", "x-requested-with"})
    @RequestMapping("/logout")
    public String logout() {
        return "forward:/";
    }

//    @RequestMapping("/token")
//    @ResponseBody
//    public Map<String, String> token(HttpSession session) {
//        return Collections.singletonMap("token", session.getId());
//    }
//    @RequestMapping("/csrf")
//    public CsrfToken csrf(CsrfToken token) {
//        return token;
//    }
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        @Autowired
        public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
            // @formatter:off
//            auth.jdbcAuthentication()
//                    .
            auth.inMemoryAuthentication()
                    .withUser("user").password("password").roles("USER")
                    .and()
                    .withUser("admin").password("admin").roles("USER", "ADMIN", "READER", "WRITER");
// @formatter:on
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.httpBasic().disable();

// @formatter:off
            http
                    .cors().and()
//                    .httpBasic().and()
                    .logout().and()
                    .authorizeRequests()
                                        .antMatchers("/**/bower_components/**", "/js/**", "/css/**", "/src/**", "/index.html", "/login", "/").permitAll()
                    .anyRequest().authenticated().and()
                    .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
            // @formatter:on
        }

        @Bean
        HeaderHttpSessionStrategy sessionStrategy() {
            return new HeaderHttpSessionStrategy();
        }
    }

}
