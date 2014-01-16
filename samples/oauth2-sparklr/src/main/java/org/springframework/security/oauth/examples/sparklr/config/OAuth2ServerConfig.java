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
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.config.annotation.authentication.configurers.InMemoryClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2ServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ServerConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author Rob Winch
 * 
 */
@Configuration
@Order(1)
public class OAuth2ServerConfig extends OAuth2ServerConfigurerAdapter {
	private static final String SPARKLR_RESOURCE_ID = "sparklr";

	@Autowired
	private TokenStore tokenStore;

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
	@DependsOn("springSecurityFilterChain")
	// FIXME remove the need for @DependsOn
	public SparklrUserApprovalHandler userApprovalHandler(OAuth2RequestFactory requestFactory) throws Exception {
		SparklrUserApprovalHandler handler = new SparklrUserApprovalHandler();
		handler.setApprovalStore(approvalStore());
		handler.setRequestFactory(requestFactory);
		return handler;
	}

	@Bean
	public ApprovalStore approvalStore() {
		TokenApprovalStore store = new TokenApprovalStore();
		store.setTokenStore(tokenStore);
		return store;
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/**/*.css");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
        http
            .authorizeRequests()
                .antMatchers("/oauth/token").fullyAuthenticated()

                .regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
                .regexMatchers(HttpMethod.GET, "/oauth/users/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
                .regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
                    .access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")

                .antMatchers("/photos").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/trusted/**").hasAnyAuthority("ROLE_CLIENT","SCOPE_TRUST")
                .antMatchers("/photos/user/**").hasAnyAuthority("ROLE_USER","SCOPE_TRUST")
                .antMatchers("/photos/**").hasAnyAuthority("ROLE_USER","SCOPE_READ")
                .and()
            .requestMatchers()
                .antMatchers("/photos/**","/oauth/token","/oauth/clients/**","/oauth/users/**")
                .and()
            .apply(new OAuth2ServerConfigurer())
                .resourceId(SPARKLR_RESOURCE_ID);
    	// @formatter:on
	}
}
