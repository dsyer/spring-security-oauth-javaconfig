/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.config.annotation.authentication.configurers.InMemoryClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author Rob Winch
 * 
 */
@Configuration
@Order(2)
public class OAuth2ServerConfig extends WebSecurityConfigurerAdapter {
	
	private static final String SPARKLR_RESOURCE_ID = "sparklr";
	
	@Autowired
	private TokenStore tokenStore;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
        http
            .authorizeRequests()
                .antMatchers("/photos").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/trusted/**").hasAnyAuthority("ROLE_CLIENT","SCOPE_TRUST")
                .antMatchers("/photos/user/**").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/**").hasAnyAuthority("ROLE_USER","SCOPE_READ")
                .and()
            .requestMatchers()
                .antMatchers("/photos/**")
                .and()
            .apply(new OAuth2ResourceServerConfigurer()).tokenStore(tokenStore)
                .resourceId(SPARKLR_RESOURCE_ID);
    	// @formatter:on
	}

	@Configuration
	@Order(1)
	protected static class AuthorizationServerConfiguration extends OAuth2AuthorizationServerConfigurerAdapter {
		
		private TokenStore tokenStore = new InMemoryTokenStore();
		
		@Autowired
		private OAuth2RequestFactory requestFactory;
		
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			
			// @formatter:off
			 	auth.apply(new InMemoryClientDetailsServiceConfigurer())
			 		.withClient("tonr")
			 			.resourceIds(SPARKLR_RESOURCE_ID)
			 			.authorizedGrantTypes("authorization_code", "implicit")
			 			.authorities("ROLE_CLIENT")
			 			.scopes("read", "write")
			 			.secret("secret");
			// @formatter:on
		}

		@Bean
		public UserApprovalHandler userApprovalHandler() throws Exception {
			SparklrUserApprovalHandler handler = new SparklrUserApprovalHandler();
			handler.setApprovalStore(approvalStore());
			handler.setRequestFactory(requestFactory);
			return handler;
		}

		@Bean
		public ApprovalStore approvalStore() throws Exception {
			TokenApprovalStore store = new TokenApprovalStore();
			store.setTokenStore(tokenStore);
			return store;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
	        http
	            .authorizeRequests()
	                .antMatchers("/oauth/token").fullyAuthenticated()

//	                .regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
//	                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
//	                .regexMatchers(HttpMethod.GET, "/oauth/users/.*")
//	                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
//	                .regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
//	                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")

	                .and()
	            .requestMatchers()
                    .antMatchers("/oauth/token")
                    .and()
	            .apply(new OAuth2AuthorizationServerConfigurer()).tokenStore(tokenStore).userApprovalHandler(userApprovalHandler());
	    	// @formatter:on
		}

	}

}
