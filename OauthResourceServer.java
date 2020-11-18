package com.sbic.turbine.ivr.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * 
 * Resource server for OAuth authentication flow.
 *
 */
@Configuration
@EnableResourceServer
public class OauthResourceServer extends ResourceServerConfigurerAdapter {
	private static final String RESOURCE_ID = "sbic-oauth2-resource";
	@Autowired
	private TokenStore tokenStore;
	/*
	 * @Autowired CustomLdapAuthenticator authenticationProvider;
	 */

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId(RESOURCE_ID).tokenStore(this.tokenStore);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests()
				.antMatchers(HttpMethod.OPTIONS, "/oauth/token", "/oauth/authorize **", "/publishes").permitAll()
				.anyRequest().authenticated();

	}
}
