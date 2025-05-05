package com.ms.demo;


import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

public class CustomOAuth2AuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

  private final SkyUser principal;

  private final String authorizedClientRegistrationId;

  /**
   * Constructs an {@code OAuth2AuthenticationToken} using the provided parameters.
   * @param principal the user {@code Principal} registered with the OAuth 2.0 Provider
   * @param authorities the authorities granted to the user
   * @param authorizedClientRegistrationId the registration identifier of the
   *
   */
  public CustomOAuth2AuthenticationToken(SkyUser principal, Collection<? extends GrantedAuthority> authorities,
      String authorizedClientRegistrationId) {
    super(authorities);
    Assert.notNull(principal, "principal cannot be null");
    Assert.hasText(authorizedClientRegistrationId, "authorizedClientRegistrationId cannot be empty");
    this.principal = principal;
    this.authorizedClientRegistrationId = authorizedClientRegistrationId;
    this.setAuthenticated(true);
  }

  @Override
  public SkyUser getPrincipal() {
    return this.principal;
  }

  @Override
  public Object getCredentials() {
    // Credentials are never exposed (by the Provider) for an OAuth2 User
    return "";
  }

  /**
   *
   * @return the registration identifier of the Authorized Client.
   */
  public String getAuthorizedClientRegistrationId() {
    return this.authorizedClientRegistrationId;
  }

}
