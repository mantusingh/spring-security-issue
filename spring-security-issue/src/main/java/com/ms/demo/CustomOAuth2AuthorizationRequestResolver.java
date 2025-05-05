package com.ms.demo;


import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * An implementation of an {@link OAuth2AuthorizationRequestResolver} that attempts to
 * resolve an {@link OAuth2AuthorizationRequest} from the provided
 * {@code HttpServletRequest} using the default request {@code URI} pattern
 * {@code /oauth2/authorization/{registrationId}}.
 *
 * <p>
 * <b>NOTE:</b> The default base {@code URI} {@code /oauth2/authorization} may be
 * overridden via it's constructor
 * {@link #CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository, String)}.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @author Eddú Meléndez
 * @author Mark Heckler
 * @since 5.1
 * @see OAuth2AuthorizationRequestResolver
 * @see OAuth2AuthorizationRequestRedirectFilter
 */
public class CustomOAuth2AuthorizationRequestResolver implements
    OAuth2AuthorizationRequestResolver {
  private static final Logger glLogger = LogManager.getLogger(CustomOAuth2AuthorizationRequestResolver.class);
  private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

  private static final char PATH_DELIMITER = '/';

  private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(
      Base64.getUrlEncoder());

  private static final StringKeyGenerator DEFAULT_SECURE_KEY_GENERATOR = new Base64StringKeyGenerator(
      Base64.getUrlEncoder().withoutPadding(), 96);

  private static final Consumer<Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
      .withPkce();

  private final ClientRegistrationRepository clientRegistrationRepository;

  private final AntPathRequestMatcher authorizationRequestMatcher;

  private Consumer<Builder> authorizationRequestCustomizer = (customizer) -> {
  };

  /**
   * Constructs a {@code DefaultOAuth2AuthorizationRequestResolver} using the provided
   * parameters.
   * @param clientRegistrationRepository the repository of client registrations
   * @param authorizationRequestBaseUri the base {@code URI} used for resolving
   * authorization requests
   */
  public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,
      String authorizationRequestBaseUri) {
    Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
    Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.authorizationRequestMatcher = new AntPathRequestMatcher(
        authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    String registrationId = resolveRegistrationId(request);
    if (registrationId == null) {
      return null;
    }
    String redirectUriAction = getAction(request, "login");
    return resolve(request, registrationId, redirectUriAction);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
    if (registrationId == null) {
      return null;
    }
    String redirectUriAction = getAction(request, "authorize");
    return resolve(request, registrationId, redirectUriAction);
  }

  /**
   * Sets the {@code Consumer} to be provided the
   * {@link Builder} allowing for further customizations.
   * @param authorizationRequestCustomizer the {@code Consumer} to be provided the
   * {@link Builder}
   * @since 5.3
   * @see OAuth2AuthorizationRequestCustomizers
   */
  public void setAuthorizationRequestCustomizer(
      Consumer<Builder> authorizationRequestCustomizer) {
    Assert.notNull(authorizationRequestCustomizer, "authorizationRequestCustomizer cannot be null");
    this.authorizationRequestCustomizer = authorizationRequestCustomizer;
  }

  private String getAction(HttpServletRequest request, String defaultAction) {
    String action = request.getParameter("action");
    if (action == null) {
      return defaultAction;
    }
    return action;
  }

  private OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId,
      String redirectUriAction) {
    if (registrationId == null) {
      return null;
    }
    ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
    if (clientRegistration == null) {
      //throw new InvalidClientRegistrationIdException("Invalid Client Registration with Id: " + registrationId);
    }
    Builder builder = getBuilder(clientRegistration);

    String redirectUriStr = expandRedirectUri(request, clientRegistration, redirectUriAction);
    //replace application_host to support white label
    var authorizationUriStr= expandAuthorizationUri(request, clientRegistration,redirectUriAction);

    // @formatter:off
    builder.clientId(clientRegistration.getClientId())
        .authorizationUri(authorizationUriStr)
        .redirectUri(redirectUriStr)
        .scopes(clientRegistration.getScopes())
        .state(DEFAULT_STATE_GENERATOR.generateKey());
    // @formatter:on

    this.authorizationRequestCustomizer.accept(builder);

    return builder.build();
  }

  private Builder getBuilder(ClientRegistration clientRegistration) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
      // @formatter:off
      Builder builder = OAuth2AuthorizationRequest.authorizationCode()
          .attributes((attrs) ->
              attrs.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()));
      // @formatter:on
      if (!CollectionUtils.isEmpty(clientRegistration.getScopes())
          && clientRegistration.getScopes().contains(OidcScopes.OPENID)) {
        // Section 3.1.2.1 Authentication Request -
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest scope
        // REQUIRED. OpenID Connect requests MUST contain the "openid" scope
        // value.
        applyNonce(builder);
      }
      if (ClientAuthenticationMethod.NONE.equals(clientRegistration.getClientAuthenticationMethod())) {
        DEFAULT_PKCE_APPLIER.accept(builder);
      }
      return builder;
    }
    throw new IllegalArgumentException(
        "Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue()
            + ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
  }

  private String resolveRegistrationId(HttpServletRequest request) {
    if (this.authorizationRequestMatcher.matches(request)) {
      return this.authorizationRequestMatcher.matcher(request)
          .getVariables()
          .get(REGISTRATION_ID_URI_VARIABLE_NAME);
    }
    return null;
  }
  private static String expandAuthorizationUri(HttpServletRequest request, ClientRegistration clientRegistration,
      String action) {
    Map<String, String> uriVariables = new HashMap<>();
    uriVariables.put("registrationId", clientRegistration.getRegistrationId());
    // @formatter:off
    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
        .replacePath(request.getContextPath())
        .replaceQuery(null)
        .fragment(null)
        .build();
    // @formatter:on
    String scheme = uriComponents.getScheme();
    uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
    String host = uriComponents.getHost();
    uriVariables.put("baseHost", (host != null) ? host : "");
    // following logic is based on HierarchicalUriComponents#toUriString()
    int port = uriComponents.getPort();
    uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
    String path = uriComponents.getPath();
    if (StringUtils.hasLength(path)) {
      if (path.charAt(0) != PATH_DELIMITER) {
        path = PATH_DELIMITER + path;
      }
    }
    uriVariables.put("basePath", (path != null) ? path : "");
    uriVariables.put("baseUrl", uriComponents.toUriString());
    uriVariables.put("action", (action != null) ? action : "");
    //replace domain name to handle white label
    var application_host= "https://" + ((host !=null) ? host : "") + ((port == -1) ? "" : ":" + port);
    uriVariables.put("application_host",application_host);
    glLogger.info("{application_host} resolved to {} and UI components are {}", application_host , uriComponents.toUriString());
    return UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getAuthorizationUri())
        .buildAndExpand(uriVariables)
        .toUriString();
  }

  /**
   * Expands the {@link ClientRegistration#getRedirectUri()} with following provided
   * variables:<br/>
   * - baseUrl (e.g. https://localhost/app) <br/>
   * - baseScheme (e.g. https) <br/>
   * - baseHost (e.g. localhost) <br/>
   * - basePort (e.g. :8080) <br/>
   * - basePath (e.g. /app) <br/>
   * - registrationId (e.g. google) <br/>
   * - action (e.g. login) <br/>
   * <p/>
   * Null variables are provided as empty strings.
   * <p/>
   * Default redirectUri is:
   * {@code org.springframework.security.config.oauth2.client.CommonOAuth2Provider#DEFAULT_REDIRECT_URL}
   * @return expanded URI
   */
  private static String expandRedirectUri(HttpServletRequest request, ClientRegistration clientRegistration,
      String action) {
    Map<String, String> uriVariables = new HashMap<>();
    uriVariables.put("registrationId", clientRegistration.getRegistrationId());
    // @formatter:off
    UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
        .replacePath(request.getContextPath())
        .replaceQuery(null)
        .fragment(null)
        .build();
    // @formatter:on
    String scheme = uriComponents.getScheme();
    uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
    String host = uriComponents.getHost();
    uriVariables.put("baseHost", (host != null) ? host : "");
    // following logic is based on HierarchicalUriComponents#toUriString()
    int port = uriComponents.getPort();
    uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
    String path = uriComponents.getPath();
    if (StringUtils.hasLength(path)) {
      if (path.charAt(0) != PATH_DELIMITER) {
        path = PATH_DELIMITER + path;
      }
    }
    uriVariables.put("basePath", (path != null) ? path : "");
    uriVariables.put("baseUrl", uriComponents.toUriString());
    uriVariables.put("action", (action != null) ? action : "");
    //replace domain name to handle white label
    var application_host= "https://" + ((host !=null) ? host : "") + ((port == -1) ? "" : ":" + port);
    uriVariables.put("application_host",application_host);
    glLogger.info("{application_host} resolved to {} and UI components are {}", application_host , uriComponents.toUriString());
    return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
        .buildAndExpand(uriVariables)
        .toUriString();
  }

  /**
   * Creates nonce and its hash for use in OpenID Connect 1.0 Authentication Requests.
   * @param builder where the {@link OidcParameterNames#NONCE} and hash is stored for
   * the authentication request
   *
   * @since 5.2
   * @see <a target="_blank" href=
   * "https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">3.1.2.1.
   * Authentication Request</a>
   */
  private static void applyNonce(Builder builder) {
    try {
      String nonce = DEFAULT_SECURE_KEY_GENERATOR.generateKey();
      String nonceHash = createHash(nonce);
      builder.attributes((attrs) -> attrs.put(OidcParameterNames.NONCE, nonce));
      builder.additionalParameters((params) -> params.put(OidcParameterNames.NONCE, nonceHash));
    }
    catch (NoSuchAlgorithmException ex) {
    }
  }

  private static String createHash(String value) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

}
