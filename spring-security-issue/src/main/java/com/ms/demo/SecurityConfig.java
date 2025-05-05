package com.ms.demo;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;


@Configuration
@EnableWebSecurity
public class SecurityConfig {


  public static final String AUTHORIZATION_REQUEST_BASE_URI = "/test/login";



  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    return new InMemoryClientRegistrationRepository(List.of(getClientRegistration()));
  }

  private ClientRegistration getClientRegistration() {
    return ClientRegistration.withRegistrationId("testapp")
        .clientId("testid")
        .clientSecret("secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .scope("read")
        .clientName("test")
        .authorizationUri("http://localhost:8080/test")
        .tokenUri("http://localhost:8080/test/oauth/token")
        .userInfoUri("http://localhost:8080/test/info")
        .userNameAttributeName("username")
        .redirectUri("localhost:8080")
        .build();
  }



  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  public OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
  }

  @Bean
  public OAuth2AuthorizedClientManager authorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository authorizedClientRepository) {

    OAuth2AuthorizedClientProvider authorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .clientCredentials()
            .password()
            .build();

    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
        new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
  }

  @Bean
  public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
    return new HttpSessionOAuth2AuthorizationRequestRepository();
  }


  @Bean
  public OAuth2AuthorizationRequestRedirectFilter oAuth2AuthorizationRequestRedirectFilter(CustomOAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver){
    return  new OAuth2AuthorizationRequestRedirectFilter(customOAuth2AuthorizationRequestResolver);
  }


  @Bean("customOAuth2AuthorizationRequestResolver")
  public CustomOAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository) {

    CustomOAuth2AuthorizationRequestResolver authorizationRequestResolver =
        new CustomOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, AUTHORIZATION_REQUEST_BASE_URI);

    return  authorizationRequestResolver;
  }

  @Bean("customOAuth2LoginAuthenticationFilter")
  @Order(PriorityOrdered.HIGHEST_PRECEDENCE)
  public CustomOAuth2LoginAuthenticationFilter customOAuth2LoginAuthenticationFilter(ClientRegistrationRepository clientRegistrationRepository,OAuth2AuthorizedClientRepository authorizedClientRepository,
      CustomOAuth2LoginAuthenticationProvider customOAuth2LoginAuthenticationProvider,
      RoleBasedAuthenticationSuccessHandler redirectRoleStrategy,OAuthAuthenticationFailureHandler oAuthAuthenticationFailureHandler){
    var customOAuth2LoginAuthenticationFilter= new CustomOAuth2LoginAuthenticationFilter(clientRegistrationRepository,authorizedClientRepository,AUTHORIZATION_REQUEST_BASE_URI);
    customOAuth2LoginAuthenticationFilter.setAuthenticationManager(new ProviderManager(customOAuth2LoginAuthenticationProvider));

    customOAuth2LoginAuthenticationFilter.setAuthenticationSuccessHandler(redirectRoleStrategy);
    customOAuth2LoginAuthenticationFilter.setAuthenticationFailureHandler(oAuthAuthenticationFailureHandler);
    return customOAuth2LoginAuthenticationFilter;
  }



  @Bean("customOAuth2LoginAuthenticationProvider")
  public CustomOAuth2LoginAuthenticationProvider customOAuth2LoginAuthenticationProvider(
      OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,CustomOAuth2UserService customOAuth2UserService){
    return  new CustomOAuth2LoginAuthenticationProvider(accessTokenResponseClient,customOAuth2UserService);
  }

  @Bean
  public DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient(){
    return new DefaultAuthorizationCodeTokenResponseClient();
  }


  @Bean
  public CustomOAuth2UserService customOAuth2UserService(){
    return new CustomOAuth2UserService();
  }

  @Bean("oAuthAuthenticationFailureHandler")
  public OAuthAuthenticationFailureHandler oAuthAuthenticationFailureHandler(){
    return  new OAuthAuthenticationFailureHandler();
  }


}
