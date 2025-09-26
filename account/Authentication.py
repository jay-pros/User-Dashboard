from typing import Optional, Tuple, Dict, Any

from django.contrib.auth import get_user_model
from django.conf import settings

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

from rest_framework_simplejwt.tokens import AccessToken, RefreshToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken


User = get_user_model()


class JWTHeaderAndCookieAuthentication(BaseAuthentication):
    """
    Authenticate requests using an access token in the Authorization header.

    If the access token is invalid or expired, this class will look for a
    refresh token in the request cookies (cookie name: 'refresh'). If a valid
    refresh token is found a new access token (and a new refresh token) will
    be created. The new access token is returned as part of the authentication
    payload so views can include it in the response body. The new refresh
    token should be set in a cookie by the view (cookie name: 'refresh').

    Usage notes:
    - Add this class to REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] or
      use it per-view via the ``authentication_classes`` decorator.
    - After authenticate() succeeds, if tokens were rotated the view can
      access the tokens on ``request._new_tokens`` or from the ``auth``
      tuple returned by DRF (see examples below).

    Example in a view (simple):
        def get(self, request):
            data = {...}
            # `auth` returned by the authenticator is available as request.auth
            if hasattr(request, '_new_tokens'):
                data['access'] = request._new_tokens['access']
                # set cookie 'refresh' with request._new_tokens['refresh']
            return Response(data)

    Security notes:
    - This implementation rotates refresh tokens by creating a fresh
      RefreshToken.for_user() and attempts to blacklist the previous one if
      token blacklisting is installed.
    """

    keyword = 'Bearer'
    refresh_cookie_name = getattr(settings, 'JWT_REFRESH_COOKIE_NAME', 'refresh')

    def authenticate(self, request) -> Optional[Tuple[Any, Any]]:
        """Return (user, auth_payload) or raise AuthenticationFailed.

        auth_payload will be a dict. If tokens were rotated the dict will
        contain new 'access' and 'refresh' string values. If authentication
        succeeded with the provided access token, the payload will contain
        'access' with the original token string.
        """
        header = get_authorization_header(request).split()
        if not header or header[0].lower() != self.keyword.lower().encode():
            return None

        if len(header) == 1:
            raise exceptions.AuthenticationFailed('Invalid Authorization header. No credentials provided.')

        token = header[1].decode()

        # Try to validate access token first
        try:
            access = AccessToken(token)
            user = self.get_user_from_token(access)
            # successful: return user and a simple payload containing the access
            auth_payload = {'access': str(access)}
            return (user, auth_payload)
        except TokenError:
            # access token invalid or expired — attempt refresh via cookie
            refresh_token = request.COOKIES.get(self.refresh_cookie_name)
            if not refresh_token:
                raise exceptions.AuthenticationFailed('Access token expired and no refresh cookie.')

            try:
                refresh = RefreshToken(refresh_token)
            except TokenError:
                raise exceptions.AuthenticationFailed('Refresh token is invalid or expired.')

            # At this point refresh token is valid. Resolve user.
            user = self.get_user_from_token(refresh)

            # Rotate refresh token: issue a new refresh token and access token
            new_refresh = RefreshToken.for_user(user)
            new_access = new_refresh.access_token

            # Try to blacklist the old refresh token if blacklist app is installed
            try:
                # Blacklist depends on rest_framework_simplejwt.token_blacklist
                # Older token instances support .blacklist() helper
                refresh.blacklist()
            except Exception:
                # If blacklisting not configured or fails, continue silently
                pass

            # Attach new tokens to the request so views/middleware can use them
            tokens = {'access': str(new_access), 'refresh': str(new_refresh)}
            request._new_tokens = tokens

            return (user, tokens)

    def get_user_from_token(self, token) -> Any:
        """Locate and return a user instance given a validated token object.

        The token payload normally contains the claim 'user_id' (SimpleJWT
        default). This helper reads that claim and returns the user. Raises
        AuthenticationFailed if the user doesn't exist.
        """
        user_id = token.payload.get('user_id') or token.payload.get('user')
        if user_id is None:
            raise exceptions.AuthenticationFailed('Token contained no recognizable user identification')

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found for provided token')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User is inactive')

        return user
