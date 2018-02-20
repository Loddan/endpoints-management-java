/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.api.server.spi.auth;

import com.google.api.Service;
import com.google.api.auth.Authenticator;
import com.google.api.auth.UserInfo;
import com.google.api.control.ConfigFilter;
import com.google.api.control.model.MethodRegistry.Info;
import com.google.api.server.spi.auth.common.User;
import com.google.api.server.spi.config.Singleton;
import com.google.common.annotations.VisibleForTesting;

/**
 * Authenticator that extracts auth token from the HTTP authorization header or
 * from the "access_token" query parameter.
 *
 * This authenticator supports the same authentication feature as in Endpoints
 * Server Proxy.
 *
 * This authenticator needs to be placed behind {@link ConfigFilter} which adds
 * {@link Info} and {@link Service} as attributes of the incoming HTTP requests.
 */
@Singleton
public final class EspAuthenticator extends AbstractEspAuthenticator {

  public EspAuthenticator() {
    super();
  }

  @VisibleForTesting
  EspAuthenticator(Authenticator authenticator) {
    super(authenticator);
  }

  @Override
  protected User userInfoToUser(UserInfo userInfo) {
    return new User(userInfo.getId(), userInfo.getEmail());
  }
}
