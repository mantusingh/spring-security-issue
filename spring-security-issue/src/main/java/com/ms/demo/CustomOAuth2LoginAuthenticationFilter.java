package com.ms.demo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class CustomOAuth2LoginAuthenticationFilter  extends AbstractAuthenticationProcessingFilter {

  /**
   * The default {@code URI} where this {@code Filter} processes authentication requests.
   */
  public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/oauth2/code/*";

  private static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

  private static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

  private ClientRegistrationRepository clientRegistrationRepository;

  private OAuth2AuthorizedClientRepository authorizedClientRepository;

  private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

  private Converter<CustomOAuth2LoginAuthenticationToken, CustomOAuth2AuthenticationToken> authenticationResultConverter = this::createAuthenticationResult;

  /**
   * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
   *
   * @param clientRegistrationRepository the repository of client registrations
   * @param authorizedClientService      the authorized client service
   */
  public CustomOAuth2LoginAuthenticationFilter(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService authorizedClientService) {
    this(clientRegistrationRepository, authorizedClientService, DEFAULT_FILTER_PROCESSES_URI);
  }

  /**
   * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
   *
   * @param clientRegistrationRepository the repository of client registrations
   * @param authorizedClientService      the authorized client service
   * @param filterProcessesUrl           the {@code URI} where this {@code Filter} will process the
   *                                     authentication requests
   */
  public CustomOAuth2LoginAuthenticationFilter(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService authorizedClientService, String filterProcessesUrl) {
    this(clientRegistrationRepository,
        new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService),
        filterProcessesUrl);
  }

  /**
   * Constructs an {@code OAuth2LoginAuthenticationFilter} using the provided parameters.
   *
   * @param clientRegistrationRepository the repository of client registrations
   * @param authorizedClientRepository   the authorized client repository
   * @param filterProcessesUrl           the {@code URI} where this {@code Filter} will process the
   *                                     authentication requests
   * @since 5.1
   */
  public CustomOAuth2LoginAuthenticationFilter(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository authorizedClientRepository, String filterProcessesUrl) {
    super(filterProcessesUrl);
    Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
    Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.authorizedClientRepository = authorizedClientRepository;
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException {
    MultiValueMap<String, String> params = toMultiMap(
        request.getParameterMap());
    if (!isAuthorizationResponse(params)) {
      OAuth2Error oauth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository
        .removeAuthorizationRequest(request, response);
    if (authorizationRequest == null) {
      OAuth2Error oauth2Error = new OAuth2Error(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE);
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    String registrationId = authorizationRequest.getAttribute(OAuth2ParameterNames.REGISTRATION_ID);
    ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(
        registrationId);
    if (clientRegistration == null) {
      OAuth2Error oauth2Error = new OAuth2Error(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE,
          "Client Registration not found with Id: " + registrationId, null);
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
    // @formatter:off
    String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
        .replaceQuery(null)
        .build()
        .toUriString();
    // @formatter:on
    OAuth2AuthorizationResponse authorizationResponse = convert(
        params,
        redirectUri);
    Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
    var authenticationRequest = new CustomOAuth2LoginAuthenticationToken(
        clientRegistration,
        new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
    authenticationRequest.setDetails(authenticationDetails);
    CustomOAuth2LoginAuthenticationToken authenticationResult = (CustomOAuth2LoginAuthenticationToken) this
        .getAuthenticationManager()
        .authenticate(authenticationRequest);
    CustomOAuth2AuthenticationToken oauth2Authentication = this.authenticationResultConverter
        .convert(authenticationResult);
    Assert.notNull(oauth2Authentication, "authentication result cannot be null");
    oauth2Authentication.setDetails(authenticationDetails);
    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
        authenticationResult.getClientRegistration(), oauth2Authentication.getName(),
        authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());

    this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication,
        request, response);
    return oauth2Authentication;
  }

  /**
   * Sets the repository for stored {@link OAuth2AuthorizationRequest}'s.
   *
   * @param authorizationRequestRepository the repository for stored
   *                                       {@link OAuth2AuthorizationRequest}'s
   */
  public final void setAuthorizationRequestRepository(
      AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
    Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
    this.authorizationRequestRepository = authorizationRequestRepository;
  }

  /**
   * Sets the converter responsible for converting from {@link OAuth2LoginAuthenticationToken} to
   * {@link OAuth2AuthenticationToken} authentication result.
   *
   * @param authenticationResultConverter the converter for {@link OAuth2AuthenticationToken}'s
   * @since 5.6
   */
  public final void setAuthenticationResultConverter(
      Converter<CustomOAuth2LoginAuthenticationToken, CustomOAuth2AuthenticationToken> authenticationResultConverter) {
    Assert.notNull(authenticationResultConverter, "authenticationResultConverter cannot be null");
    this.authenticationResultConverter = authenticationResultConverter;
  }

  private CustomOAuth2AuthenticationToken createAuthenticationResult(
      CustomOAuth2LoginAuthenticationToken authenticationResult) {
    return new CustomOAuth2AuthenticationToken(authenticationResult.getPrincipal(),
        authenticationResult.getAuthorities(),
        authenticationResult.getClientRegistration().getRegistrationId());


  }

   MultiValueMap<String, String> toMultiMap(Map<String, String[]> map) {
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>(map.size());
    map.forEach((key, values) -> {
      if (values.length > 0) {
        for (String value : values) {
          params.add(key, value);
        }
      }
    });
    return params;
  }

   boolean isAuthorizationResponse(MultiValueMap<String, String> request) {
    return isAuthorizationResponseSuccess(request) || isAuthorizationResponseError(request);
  }

   boolean isAuthorizationResponseSuccess(MultiValueMap<String, String> request) {
    return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.CODE))
        && StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
  }

   boolean isAuthorizationResponseError(MultiValueMap<String, String> request) {
    return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.ERROR))
        && StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
  }

   OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
    String code = request.getFirst(OAuth2ParameterNames.CODE);
    String errorCode = request.getFirst(OAuth2ParameterNames.ERROR);
    String state = request.getFirst(OAuth2ParameterNames.STATE);
    if (StringUtils.hasText(code)) {
      return OAuth2AuthorizationResponse.success(code).redirectUri(redirectUri).state(state).build();
    }
    String errorDescription = request.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
    String errorUri = request.getFirst(OAuth2ParameterNames.ERROR_URI);
    // @formatter:off
    return OAuth2AuthorizationResponse.error(errorCode)
        .redirectUri(redirectUri)
        .errorDescription(errorDescription)
        .errorUri(errorUri)
        .state(state)
        .build();
    // @formatter:on
  }
}