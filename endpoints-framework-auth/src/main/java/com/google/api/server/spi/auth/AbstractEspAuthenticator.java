package com.google.api.server.spi.auth;

import com.google.api.Service;
import com.google.api.auth.Authenticator;
import com.google.api.auth.UnauthenticatedException;
import com.google.api.auth.UserInfo;
import com.google.api.control.ConfigFilter;
import com.google.api.control.model.MethodRegistry;
import com.google.api.server.spi.auth.common.User;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.util.concurrent.UncheckedExecutionException;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

/**
 * Abstract authenticator that extracts auth token from the HTTP authorization
 * header or from the "access_token" query parameter.
 *
 * This authenticator supports the same authentication feature as in Endpoints
 * Server Proxy.
 *
 * This authenticator needs to be placed behind {@link ConfigFilter} which adds
 * {@link MethodRegistry.Info} and {@link Service} as attributes of the incoming HTTP requests.
 */
public abstract class AbstractEspAuthenticator implements com.google.api.server.spi.config.Authenticator {
  private static final Logger logger = Logger.getLogger(EspAuthenticator.class.getName());

  private final Authenticator authenticator;

  public AbstractEspAuthenticator() {
    this(Authenticator.create());
  }

  @VisibleForTesting
  AbstractEspAuthenticator(Authenticator authenticator) {
    this.authenticator = authenticator;
  }

  @Override
  public final User authenticate(HttpServletRequest request) {
    MethodRegistry.Info methodInfo = ConfigFilter.getMethodInfo(request);
    if (methodInfo == null) {
      throw new IllegalStateException("method_info is not set in the request");
    }
    Optional<MethodRegistry.AuthInfo> authInfo = methodInfo.getAuthInfo();
    if (!authInfo.isPresent()) {
      logger.info("auth is not configured for this request");
      return null;
    }

    Service service = ConfigFilter.getService(request);
    if (service == null) {
      throw new IllegalStateException("service is not set in the request");
    }

    String serviceName = service.getName();

    try {
      UserInfo userInfo = this.authenticator.authenticate(request, authInfo.get(), serviceName);
      return userInfoToUser(userInfo);
    } catch (UnauthenticatedException | UncheckedExecutionException exception) {
      logger.warning(String.format("Authentication failed: %s", exception));
      return null;
    }
  }

  protected abstract User userInfoToUser(UserInfo userInfo);
}
