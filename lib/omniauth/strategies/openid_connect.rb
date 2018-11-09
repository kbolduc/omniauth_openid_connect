require 'addressable/uri'
require 'date'
require 'timeout'
require 'net/http'
require 'open-uri'
require 'omniauth'
require 'openid_connect'

module OmniAuth
  module Strategies
    class OpenIDConnect
      include OmniAuth::Strategy

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: 'https',
        host: nil,
        port: 443,
        authorization_endpoint: '/authorize',
        token_endpoint: '/token',
        userinfo_endpoint: '/userinfo',
        jwks_uri: '/jwk',
        end_session_endpoint: nil
      }
      option :issuer
      option :discovery, false
      option :client_signing_alg
      option :client_jwk_signing_key
      option :client_x509_signing_key
      option :scope, [:openid]
      option :response_type, "code"
      option :state
      option :response_mode
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :hd, nil
      option :max_age
      option :ui_locales
      option :id_token_hint
      option :acr_values
      option :send_nonce, true
      option :send_scope_to_token_endpoint, true
      option :client_auth_method
      option :post_logout_redirect_uri
      option :refresh_expired_access_token, true
      option :expires_latency, 0

      
      # Shared constants to ensure the reference to the session stay "linked"
      SESSION_PREFIX="openid_connect".freeze
      SESSION_TYPE_ACCESS_TOKEN="access_token".freeze
      SESSION_TYPE_EXPIRES_AT="expires_at".freeze
      SESSION_TYPE_TOKEN_TYPE="token_type".freeze
      SESSION_TYPE_ID_TOKEN="id_token".freeze
      SESSION_TYPE_REFRESH_TOKEN="refresh_token".freeze
      SESSION_TYPE_REFRESH_EXPIRES_AT="refresh_expires_at".freeze
      SESSION_TYPE_SCOPE="scope".freeze
      

      uid { user_info.sub }

      info do
        {
          name: user_info.name,
          email: user_info.email,
          nickname: user_info.preferred_username,
          first_name: user_info.given_name,
          last_name: user_info.family_name,
          gender: user_info.gender,
          image: user_info.picture,
          phone: user_info.phone_number,
          urls: { website: user_info.website }
        }
      end

      extra do
        { raw_info: user_info.raw_attributes }
      end

      credentials do
        {
          id_token: access_token.id_token,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(client_options)
      end

      def config
        @config ||= ::OpenIDConnect::Discovery::Provider::Config.discover!(options.issuer)
      end

      def request_phase
        discover!
        redirect authorize_uri
      end

      def callback_phase
        error = request.params['error_reason'] || request.params['error']
        if error
          raise CallbackError.new(request.params['error'], request.params['error_description'] || request.params['error_reason'], request.params['error_uri'])
        elsif request.params['state'].to_s.empty? || request.params['state'] != stored_state
          return Rack::Response.new(['401 Unauthorized'], 401).finish
        elsif !request.params['code']
          return fail!(:missing_code, OmniAuth::OpenIDConnect::MissingCodeError.new(request.params['error']))
        else
          discover!
          client.redirect_uri = redirect_uri
          client.authorization_code = authorization_code
          access_token
          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue Rack::OAuth2::Client::Error => e
        fail!(e.response[:error].to_sym, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      # RP-Initiated Logout
      # https://openid.net/specs/openid-connect-session-1_0.html#rfc.section.5
      #
      # Rails Example:
      # redirect_to "/auth/:provider_name/logout"
      #
      def logout_phase
        # Discover to initialize the end_session_endpoint
        discover!

        # Fetch the id_token_hint from the request.params['id_token_hint'] or the stored id_token in the session to send
        # with redirect to the endsession endpoint
        _id_token = request.params['id_token_hint'] || stored_id_token

        if end_session_endpoint_is_valid? && _id_token
          log(:info, "RP-Initiated Logout, redirecting to: #{client_options.end_session_endpoint}")
          return redirect(end_session_uri(_id_token))
        end

        # return back nothing if the logout phase has been call but is invalid (should not be)
        log(:error, "Failed to start RP-Initiated Logout.")
        return
      end

      # Refresh token phase which will call the token endpoint using the refresh_token grant type and the stored
      # refresh token that was issue upon early authorization. The access token payload will then be persisted in the
      # session for future use and detection of access token expiry.
      def refresh_token_phase
        discover!
        refresh_access_token
      rescue ::Rack::OAuth2::Client::Error => e
        if(e.response && e.response[:error] && e.response[:error].to_sym == :invalid_grant)
          delete_stored_access_token_in_session
          return fail!(:refresh_token_invalid_grant, ::OmniAuth::OpenIDConnect::RefreshTokenInvalidGrant.new(e.response[:error_description]))
        end
        fail!(e.response[:error].to_sym, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end


      def other_phase
        refresh_token_phase if should_execute_refresh_token_phase?

        # Logout Phase
        if current_path && logout_path_pattern.match(current_path)
          # Is the current path matching the omniauth local endpoint (request_path + '/logout')
          logout_phase_response = logout_phase
          # If there is no response from the logout phase then do not return, allowing call_app! to be called.
          return logout_phase_response if logout_phase_response
        end
        
        call_app!
      end

      def authorization_code
        request.params['code']
      end

      def end_session_uri(id_token=nil)
        return unless end_session_endpoint_is_valid?
        end_session_uri = URI(client_options.end_session_endpoint)
        end_session_uri.query = encoded_end_session_uri_query(id_token)
        end_session_uri.to_s
      end

      def authorize_uri
        client.redirect_uri = redirect_uri
        opts = {
          response_type: options.response_type,
          scope: options.scope,
          state: new_state,
          login_hint: request.params['login_hint'],
          ui_locales: request.params['ui_locales'],
          claims_locales: request.params['claims_locales'],
          prompt: request.params['prompt'],
          nonce: (new_nonce if options.send_nonce),
          hd: options.hd,
        }
        client.authorization_uri(opts.reject { |k, v| v.nil? })
      end

      def public_key
        return config.jwks if options.discovery
        key_or_secret
      end

      protected

      # This method with take the OmniAuth Provider name specified in the configuration, and a support "session type".
      # The types of sessions are all pertaining to the contents of the access token. State being managed by the omniauth
      # strategy will offer more OIDC functionality, w
      def self.get_session_key(provider_name, session_type)
        return unless provider_name && session_type

        _session_key_prefix="#{SESSION_PREFIX}.#{provider_name.to_s.downcase.tr_s(' ', '_')}."

        case session_type.to_s.downcase
        when SESSION_TYPE_ACCESS_TOKEN
          return "#{_session_key_prefix}#{SESSION_TYPE_ACCESS_TOKEN}"
        when SESSION_TYPE_EXPIRES_AT
          return "#{_session_key_prefix}#{SESSION_TYPE_EXPIRES_AT}"
        when SESSION_TYPE_TOKEN_TYPE
          return "#{_session_key_prefix}#{SESSION_TYPE_TOKEN_TYPE}"
        when SESSION_TYPE_ID_TOKEN
          return "#{_session_key_prefix}#{SESSION_TYPE_ID_TOKEN}"
        when SESSION_TYPE_REFRESH_TOKEN
          return "#{_session_key_prefix}#{SESSION_TYPE_REFRESH_TOKEN}"
        when SESSION_TYPE_REFRESH_EXPIRES_AT
          return "#{_session_key_prefix}#{SESSION_TYPE_REFRESH_EXPIRES_AT}"
        when SESSION_TYPE_SCOPE
          return "#{_session_key_prefix}#{SESSION_TYPE_SCOPE}"
        else
          return nil
        end
      end

      private

      def issuer
        resource = "#{ client_options.scheme }://#{ client_options.host }"
        resource = "#{ resource }:#{ client_options.port }" if client_options.port
        ::OpenIDConnect::Discovery::Provider.discover!(resource).issuer
      end

      def discover!
        return unless options.discovery
        options.issuer = issuer if options.issuer.blank?
        setup_client_options(config)
      end

      def setup_client_options(discover)
        client_options.authorization_endpoint = discover.authorization_endpoint
        client_options.token_endpoint = discover.token_endpoint
        client_options.userinfo_endpoint = discover.userinfo_endpoint
        client_options.jwks_uri = discover.jwks_uri
        client_options.end_session_endpoint = discover.end_session_endpoint
      end

      def user_info
        @user_info ||= access_token.userinfo!
      end

      def access_token
        @access_token ||= begin
          _access_token = client.access_token!(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: options.client_auth_method
          )
          # Set the time before decoding and verifying the id_token to ensure most accurate expiry time
          _time = Time.now

          _id_token = decode_id_token _access_token.id_token
          _id_token.verify!(
            issuer: options.issuer,
            client_id: client_options.identifier,
            nonce: stored_nonce
          )

          # return the full access token
          store_access_token_in_session(_access_token, _time)
        end
      end

      # Refresh the access token using the refresh_token grant_type.
      def refresh_access_token
        # Ensure the refresh token has a value before attempting to excuting the POST to the IdP
        return unless stored_refresh_token

        # Set the refresh_token to the client to send the refresh token, by doing so it also using the "refresh_token"
        # grant_type.
        client.refresh_token=stored_refresh_token

        log(:info, "Refreshing Access Token.")
        
        @access_token ||= begin
          _access_token = client.access_token!(
            scope: (options.scope if options.send_scope_to_token_endpoint),
            client_auth_method: :client_credentials
          )

          # return the full access token
          store_access_token_in_session(_access_token, Time.now)
        end
      end

      ##################################################################################################################
      # Utility methods
      ##################################################################################################################

      # Send the expires_in value, the amount of seconds from now, in which a token will expire. If the value is equal
      # to Zero, then it will be presumed that it will never expire and a value of 0 will be return
      # Returns back the time in seconds.
      def expires_as_time_in_seconds(expires_in, time=Time.now)
        return 0 unless expires_in && expires_in > 0
        _expires_latency = (options.expires_latency && options.expires_latency.to_i > 0)? options.expires_latency.to_i : 0
        (time.to_i + expires_in.to_i) - _expires_latency
      end

      def access_token_expired?
        _stored_expires_at = stored_expires_at
        return false unless _stored_expires_at != nil && _stored_expires_at >0

        # If the access token expiry time is greater than or equal to the current time, then the token is expired
        access_token_is_expired = (_stored_expires_at <= Time.now.to_i)
        log(:info, "Access Token expired!") if access_token_is_expired
        access_token_is_expired
      end

      def refresh_token_expired?
        _stored_refresh_expires_at = stored_refresh_expires_at
        return false unless _stored_refresh_expires_at != nil && _stored_refresh_expires_at >0

        # If the refresh token expiry time is greater than or equal to the current time, then the token is expired
        refresh_token_is_expired = (_stored_refresh_expires_at <= Time.now.to_i)
        log(:info, "Refresh Token expired!") if refresh_token_is_expired
        refresh_token_is_expired
      end

      # Returns true if the refresh token phase should be executed.
      # opt: options.refresh_expired_access_token
      def should_execute_refresh_token_phase?
        return false unless options.refresh_expired_access_token.eql?(true) && current_path && !current_path.start_with?(path_prefix)
        stored_refresh_token != nil && access_token_expired? && refresh_token_expired? != true
      end

      def decode_id_token(id_token)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, public_key)
      end

      def client_options
        options.client_options
      end

      def new_state
        state = options.state.call if options.state.respond_to? :call
        session['omniauth.state'] = state || SecureRandom.hex(16)
      end

      def stored_state
        session.delete('omniauth.state')
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete('omniauth.nonce')
      end

      # This will take an access token and store specific attributes in the session that may be needed to be reference
      # by the client application. eg: access_token value for resource servers. Others are to assist with refresh and
      # RP Initiated Logouts.
      def store_access_token_in_session(access_token, time=Time.now)
        new_stored_access_token(access_token.access_token)
        new_stored_expires_at(expires_as_time_in_seconds(access_token.expires_in, time))
        new_stored_token_type(access_token.token_type)
        new_stored_scope(access_token.scope)

        # oidc id_token, used for RP initiated logout
        new_stored_id_token(access_token.id_token)

        if options.refresh_expired_access_token.eql?(true) && access_token.refresh_token
          new_stored_refresh_token(access_token.refresh_token)
          new_stored_refresh_expires_at(expires_as_time_in_seconds(access_token.raw_attributes['refresh_expires_in'], time)) if access_token.raw_attributes.has_key?('refresh_expires_in')
        else
          delete_stored_refresh
        end

        # return the access_token entity itself (passthrough)
        access_token
      end

      # OIDC Access Token Session Storage
      # Access Token - The actual Access Token
      def stored_access_token
        session[self.class.get_session_key(name, SESSION_TYPE_ACCESS_TOKEN)]
      end
      def new_stored_access_token(access_token)
        session[self.class.get_session_key(name, SESSION_TYPE_ACCESS_TOKEN)]=access_token
      end
      # Access Token - Expires at time, in seconds, when the actual access token expires
      def stored_expires_at
        session[self.class.get_session_key(name, SESSION_TYPE_EXPIRES_AT)]
      end
      def new_stored_expires_at(expires_at)
        session[self.class.get_session_key(name, SESSION_TYPE_EXPIRES_AT)]=expires_at
      end
      # Access Token - Token Type (of the access token)
      def stored_token_type
        session[self.class.get_session_key(name, SESSION_TYPE_TOKEN_TYPE)]
      end
      def new_stored_token_type(token_type)
        session[self.class.get_session_key(name, SESSION_TYPE_TOKEN_TYPE)]=token_type
      end
      # Access Token - Id Token
      def stored_id_token
        session[self.class.get_session_key(name, SESSION_TYPE_ID_TOKEN)]
      end
      def new_stored_id_token(refresh_token)
        session[self.class.get_session_key(name, SESSION_TYPE_ID_TOKEN)]=refresh_token
      end

      # Access Token - Refresh Token
      def stored_refresh_token
        session[self.class.get_session_key(name, SESSION_TYPE_REFRESH_TOKEN)]
      end
      def new_stored_refresh_token(refresh_token)
        session[self.class.get_session_key(name, SESSION_TYPE_REFRESH_TOKEN)]=refresh_token
      end
      # Access Token - Refresh Token Expires In, seconds
      def stored_refresh_expires_at
        session[self.class.get_session_key(name, SESSION_TYPE_REFRESH_EXPIRES_AT)]
      end
      def new_stored_refresh_expires_at(refresh_expires_at)
        session[self.class.get_session_key(name, SESSION_TYPE_REFRESH_EXPIRES_AT)]=refresh_expires_at
      end
      def delete_stored_refresh
        session.delete(self.class.get_session_key(name, SESSION_TYPE_REFRESH_TOKEN))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_REFRESH_EXPIRES_AT))
      end
      
      # Access Token - Scopes being return with access token, could update on token refresh.
      def stored_scope
        session[self.class.get_session_key(name, SESSION_TYPE_SCOPE)]
      end
      def new_stored_scope(scope)
        session[self.class.get_session_key(name, SESSION_TYPE_SCOPE)]=scope
      end

      def delete_stored_access_token_in_session
        session.delete(self.class.get_session_key(name, SESSION_TYPE_ACCESS_TOKEN))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_EXPIRES_AT))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_TOKEN_TYPE))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_ID_TOKEN))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_SCOPE))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_REFRESH_TOKEN))
        session.delete(self.class.get_session_key(name, SESSION_TYPE_REFRESH_EXPIRES_AT))
      end

      def str_parameterized(value)
        return unless value
        value.to_s.downcase.tr_s(' ', '_')
      end

      def session
        return {} if @env.nil?
        super
      end

      def key_or_secret
        case options.client_signing_alg
        when :HS256, :HS384, :HS512
          return client_options.secret
        when :RS256, :RS384, :RS512
          if options.client_jwk_signing_key
            return parse_jwk_key(options.client_jwk_signing_key)
          elsif options.client_x509_signing_key
            return parse_x509_key(options.client_x509_signing_key)
          end
        else
        end
      end

      def parse_x509_key(key)
        OpenSSL::X509::Certificate.new(key).public_key
      end

      def parse_jwk_key(key)
        json = JSON.parse(key)
        if json.has_key?('keys')
          JSON::JWK::Set.new json['keys']
        else
          JSON::JWK.new json
        end
      end

      def decode(str)
        UrlSafeBase64.decode64(str).unpack('B*').first.to_i(2).to_s
      end

      def redirect_uri
        return client_options.redirect_uri unless request.params['redirect_uri']
        "#{ client_options.redirect_uri }?redirect_uri=#{ CGI.escape(request.params['redirect_uri']) }"
      end

      # def is_id_token_valid?(id_token, expected = {})
      #   return false unless id_token
      #   _decoded_id_token = id_token.kind_of?(::OpenIDConnect::ResponseObject::IdToken)? id_token : decode_id_token(id_token)
      #
      #   return false unless _decoded_id_token.exp.to_i > Time.now.to_i
      #   return false unless _decoded_id_token.iss == (options.issuer || expected[:issuer])
      #   # aud(ience) can be a string or an array of strings
      #   unless Array(_decoded_id_token.aud).include?(client_options.identifier || expected[:client_id])
      #     return false
      #   end
      #
      #   true
      # end
      
      def encoded_end_session_uri_query(id_token)
        end_session_query_hash={}
        end_session_query_hash[:id_token_hint] = id_token
        end_session_query_hash[:post_logout_redirect_uri] = options.post_logout_redirect_uri if is_valid_url? options.post_logout_redirect_uri
        URI.encode_www_form(end_session_query_hash)
      end

      def end_session_endpoint_is_valid?
        client_options.end_session_endpoint != nil
      end

      def logout_path_pattern
        %r{\A#{Regexp.quote(request_path)}(/logout)}
      end

      def is_valid_url?(url)
        return false unless url
        uri = URI.parse(url)
        uri.kind_of?( URI::HTTPS ) || uri.kind_of?( URI::HTTP )
      rescue URI::InvalidURIError => e
        log(:error, e.message)
        false
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
