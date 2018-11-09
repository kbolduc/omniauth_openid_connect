##
# session_helper.rb
#
# This module is to assist client applications to get reference to the session state data.
#
module OmniAuth
  module OpenIDConnect
    module SessionHelper

      ##
      # Returns the omniauth session key to reference the access token in the session
      #
      def omniauth_access_token_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_ACCESS_TOKEN)
      end

      ##
      # Returns the omniauth session key to reference the access token, expires at, in the session
      #
      def omniauth_expires_at_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_EXPIRES_AT)
      end

      ##
      # Returns the omniauth session key to reference the access token, token type, in the session
      #
      def omniauth_token_type_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_TOKEN_TYPE)
      end

      ##
      # Returns the omniauth session key to reference the refresh token in the session
      #
      def omniauth_refresh_token_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_REFRESH_TOKEN)
      end

      ##
      # Returns the omniauth session key to reference the refresh token, expires at, in the session
      #
      def omniauth_refresh_expires_at_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_REFRESH_EXPIRES_AT)
      end

      ##
      # Returns the omniauth session key to reference the scopes granted with the access token, in the session
      #
      def omniauth_scope_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_SCOPE)
      end

      ##
      # Returns the omniauth session key to reference the OIDC id token in the session
      #
      def omniauth_id_token_key(provider_name)
        ::OmniAuth::Strategies::OpenIDConnect.get_session_key(provider_name, ::OmniAuth::Strategies::OpenIDConnect::SESSION_TYPE_ID_TOKEN)
      end
    end
  end
end