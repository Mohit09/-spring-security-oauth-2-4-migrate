package com.sbic.turbine.ivr.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@Configuration
@EnableOAuth2Client
public class Oauth2ClientConfig {
	@Bean
	public OAuth2ProtectedResourceDetails clientCredentails() {
		return new ClientCredentialsResourceDetails();
	}

}
