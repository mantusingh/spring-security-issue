package com.ms.demo;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuthAuthenticationFailureHandler implements AuthenticationFailureHandler {

  /**
   * Called when an authentication attempt fails.
   *
   * @param request   the request during which the authentication attempt occurred.
   * @param response  the response.
   * @param exception the exception which was thrown to reject the authentication request.
   */
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {

  }
}
