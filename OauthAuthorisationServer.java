package com.sbic.turbine.ivr.security;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.sbic.turbine.ivr.config.MySqlDataSourceConfig;

/**
 * Authorisation Server for OAuth authentication/authorisation.
 *
 */

@Configuration
@EnableAuthorizationServer
public class OauthAuthorisationServer extends AuthorizationServerConfigurerAdapter {
	@Autowired
	ClientDetailsService clientDetailsService;
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	MySqlDataSourceConfig mysqlDataSource;

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(mysqlDataSource.primaryDataSource()).passwordEncoder(NoOpPasswordEncoder.getInstance()); // TODO Auto-generated
																								// method stub
		// super.configure(clients);
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(this.authenticationManager).tokenStore(tokenStore())
				.userApprovalHandler(userApprovalHandler()).accessTokenConverter(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		final RsaSigner signer = new RsaSigner(KeyConfig.getSignerKey());

		JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
			private JsonParser objectMapper = JsonParserFactory.create();

			@Override
			protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				String content;
				try {
					content = this.objectMapper
							.formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
				} catch (Exception ex) {
					throw new IllegalStateException("Cannot convert access token to JSON", ex);
				}
				Map<String, String> headers = new HashMap<>();
				headers.put("kid", KeyConfig.VERIFIER_KEY_ID);
				String token = JwtHelper.encode(content, signer, headers).getEncoded();
				return token;
			}
		};
		converter.setSigner(signer);
		converter.setVerifier(new RsaVerifier(KeyConfig.getVerifierKey()));
		return converter;
	}

	@Bean
	public ApprovalStore approvalStore() {
		return new JdbcApprovalStore(mysqlDataSource.primaryDataSource());
	}

	@Bean
	public JWKSet jwkSet() {
		RSAKey.Builder builder = new RSAKey.Builder(KeyConfig.getVerifierKey()).keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS256).keyID(KeyConfig.VERIFIER_KEY_ID);
		return new JWKSet(builder.build());
	}

	@Bean
	public UserApprovalHandler userApprovalHandler() {
		// TODO Auto-generated method stub
		ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
		userApprovalHandler.setApprovalStore(approvalStore());
		userApprovalHandler.setClientDetailsService(this.clientDetailsService);
		userApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(this.clientDetailsService));
		return userApprovalHandler;
	}

	@Bean
	public TokenStore tokenStore() {
		// TODO Auto-generated method stub
		JwtTokenStore tokenStore = new JwtTokenStore(accessTokenConverter());
		tokenStore.setApprovalStore(approvalStore());
		return tokenStore;
	}

	/*
	 * @Bean(name = "mysqlDS")
	 * 
	 * @Primary
	 * 
	 * @ConfigurationProperties(prefix = "spring.datasource") public DataSource
	 * primaryDataSource() {
	 * 
	 * HikariDataSource hikariDataSource = new HikariDataSource();
	 * hikariDataSource.setDriverClassName("com.mysql.jdbc.Driver");
	 * hikariDataSource.setJdbcUrl("jdbc:mysql://172.16.125.57:8882/turbine");
	 * 
	 * hikariDataSource.setUsername("turbine");
	 * 
	 * hikariDataSource.setPassword("Sbicard@123");
	 * hikariDataSource.setMinimumIdle(1000);
	 * hikariDataSource.setMaximumPoolSize(10); return hikariDataSource;
	 * 
	 * // return DataSourceBuilder.create().build(); }
	 */

}
