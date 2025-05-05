package com.ms.demo;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class NoopAuthManager implements AuthenticationManager {
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
	}
}
