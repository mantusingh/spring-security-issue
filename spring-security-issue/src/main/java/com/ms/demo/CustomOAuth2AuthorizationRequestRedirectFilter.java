package com.ms.demo;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;


public class CustomOAuth2AuthorizationRequestRedirectFilter extends
    OAuth2AuthorizationRequestRedirectFilter {
  protected final Log logger = LogFactory.getLog(getClass());

  /**
   * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
   *
   * @param clientRegistrationRepository the repository of client registrations
   * @param authorizationRequestBaseUri  the base {@code URI} used for authorization requests
   */
  public CustomOAuth2AuthorizationRequestRedirectFilter(
      ClientRegistrationRepository clientRegistrationRepository,
      String authorizationRequestBaseUri) {
    super(clientRegistrationRepository, authorizationRequestBaseUri);
    logger.info("authorizationRequestBaseUri " + authorizationRequestBaseUri);
  }
}

