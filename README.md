## Authentication and Authorization with Spring Security - JWT

This project focuses on implementing JSON Web Token (JWT) authentication and authorization for securing web services.

👉 [For more information, you can check out my blog post.]()

### Pre-requisites

- IDE
- JDK 17+
- Gradle 7.5+

### Structure

```
└── src
    ├── main
    │   ├── java
    │   │   └── com.ayseozcan
    │   │       ├── config
    │   │       │   └── security
    │   │       │       ├── JwtFilter
    │   │       │       ├── JwtUserDetails
    │   │       │       └── SecurityConfig
    │   │       ├── controller
    │   │       │   └── AuthController    
    │   │       ├── dto
    │   │       │   ├── LoginRequestDto
    │   │       │   └── RegisterRequestDto
    │   │       ├── repository
    │   │       │   ├── entity
    │   │       │   │   └── Auth    
    │   │       │   ├── enums
    │   │       │   │   └── Role      
    │   │       │   └── IAuthRepository 
    │   │       ├── service 
    │   │       │   ├── AuthService
    │   │       │   └── JwtService   
    │   │       ├── utility 
    │   │       │   └── PasswordEncoding  
    │   │       └── AuthServiceApplication
    │   └── resources
    │       └── application.yaml
    └── test
        ├── java
        ├── com.ayseozcan
        └── AuthServiceApplicationTests
```
### Dependencies

| Name                   | Implementation                                            | Version |
|------------------------|-----------------------------------------------------------|---------|
| `spring-boot-web`      | "org.springframework.boot:spring-boot-starter-web"        | 3.2.1   |
| `spring-boot-security` | "org.springframework.boot:spring-boot-starter-security"   | 3.2.1   | 
| `jwt`                  | "com.auth0:java-jwt"                                      | 4.4.0   |
| `spring-boot-jpa`      | "org.springframework.boot:spring-boot-starter-data-jpa"   | 3.2.1   |
| `postgreSql`           | "org.postgresql:postgresql "                              | 42.6.0  |
| `validation`           | "org.springframework.boot:spring-boot-starter-validation" | 3.2.1   |
| `lombok`               | "org.projectlombok:lombok "                               | 1.18.26 |

### Scripts
- JwtService
```java
@Service
public class JwtService {

    @Value("${security.oauth2.jwt.secret-key}")
    private String secretKey;

    public Optional<String> createToken(Long id) {
        String token;
        Long expireDate = 1000L * 60 * 5;
        try {
            Date issuedAt = new Date();
            Date expiresAt = new Date(System.currentTimeMillis() + expireDate);
            token = JWT.create()
                    .withClaim("id", id)
                    .withIssuer("test")
                    .withIssuedAt(issuedAt)
                    .withExpiresAt(expiresAt)
                    .sign(Algorithm.HMAC512(secretKey));
            return Optional.of(token);
        } catch (Exception exception) {
            return Optional.empty();
        }
    }

    public Optional<Long> getIdFromToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(secretKey);
            JWTVerifier jwtVerifier = JWT.require(algorithm)
                    .withIssuer("test")
                    .build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            Date expiresAt = decodedJWT.getExpiresAt();
            if (expiresAt != null && expiresAt.after(new Date())) {
                return Optional.of(decodedJWT.getClaim("id").asLong());
            } else {
                return Optional.empty();
            }
        } catch (Exception exception) {
            return Optional.empty();
        }
    }
}
```
- JwtUserDetails
```java
@Service
@RequiredArgsConstructor
public class JwtUserDetails implements UserDetailsService {

    private final AuthService authService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }

    public UserDetails getUserByAuthId(Long id) {
        Optional<Auth> auth = authService.findById(id);
        if (auth.isEmpty()) {
            return null;
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(auth.get().getRole().name()));
        return User.builder()
                .username(auth.get().getUsername())
                .password("")
                .accountExpired(false)
                .accountLocked(false)
                .authorities(authorities)
                .build();
    }
}
```
- JwtFilter
```java
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final JwtUserDetails jwtUserDetails;

    public JwtFilter(JwtService jwtService, JwtUserDetails jwtUserDetails) {
        this.jwtService = jwtService;
        this.jwtUserDetails = jwtUserDetails;
    }
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeaderParameters = request.getHeader("Authorization");
        if (authHeaderParameters != null && authHeaderParameters.startsWith("Bearer ")
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = authHeaderParameters.substring(7);
            Optional<Long> authId = jwtService.getIdFromToken(token);
            if (authId.isPresent()) {
                UserDetails userDetails = jwtUserDetails.getUserByAuthId(authId.get());
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                try {
                    throw new Exception("Token create error");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
```
- PasswordEncoding
```java
@Configuration
public class PasswordEncoding {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```
- AuthService (Register - using passwordEncoder)
```java
@Service
public class AuthService {
    private final IAuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(IAuthRepository authRepository, PasswordEncoder passwordEncoder) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<Auth> findById(Long authId) {
        return authRepository.findById(authId);
    }

    public Boolean register(RegisterRequestDto dto) {

        if (authRepository.findOptionalByUsername(dto.getUsername()).isPresent()) {
            throw new RuntimeException("User already exist");
        }
        authRepository.save(Auth.builder().name(dto.getName())
                .surname(dto.getSurname())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .build());
        return true;
    }
}
```
- SecurityConfig
```java
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(r -> r.requestMatchers("api/v1/auth/register", "api/v1/auth/login").permitAll()
                        .requestMatchers("api/v1/auth/find-all").hasRole(Role.ROLE_ADMIN.getValue())
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}
```
### Configuration of application.yaml 

```yaml
server:
  port: 8081

spring:
  datasource:
    driver-class-name: org.postgresql.Driver
    username: postgres
    password: ${POSTGRES_PASS}
    url: jdbc:postgresql://localhost:5432/SecurityExample
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true 
security:
  oauth2:
   jwt:
    secret-key: 0vTBpYERpB0QdLo9ZCxKhM6hj311g1I3
```
### Getting started

1. Clone the project.
```
https://github.com/ayse-ozcan/spring-boot-security-jwt.git
```
2. If you have Docker installed locally, you can quickly start PostgreSQL servers using Docker.
```
docker run -d --name some-postgres -e POSTGRES_PASSWORD=secret -e PGDATA=/var/lib/postgresql/data/pgdata -v /custom/mount:/var/lib/postgresql/data -p 5432:5432 postgres
```
3. Run project.
4. Open Postman.
- Send a POST request to register: `http://localhost:8081/api/v1/auth/register`
- Send a POST request to log in : `http://localhost:8081/api/v1/auth/login`
- After successfully logging in, a token will be created.
- Send a GET request to : `http://localhost:8081/api/v1/auth/find-all`
- Make sure to add the Bearer Token in the Authorization section. 
- You will observe that, if your role is admin, you can access all users; otherwise, you cannot.