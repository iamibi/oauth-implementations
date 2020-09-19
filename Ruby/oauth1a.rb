# oauth1a.rb
#
# A Concrete implementation of OAuth 1.0 using Rest-Client protocol which can be
# used for authentication by various services. This class can be inherited and
# used freely as long as it adheres to the License terms.
#
# Created By: Ibrahim
# Date: 19/September/2020

require 'rest-client'
require 'cgi'
require 'openssl'

class OAuth1
    HTTP_METHOD_GET  = 'GET'
    HTTP_METHOD_POST = 'POST'

    def initialize(consumer_key, consumer_secret)
        @consumer_key = consumer_key
        @consumer_secret = @consumer_secret
    end

    protected

    # Concrete Implementation of OAuth 1.0
    # * url_request: The API URL for which you want to make request for.
    # * request_method: HTTP GET/POST method to be performed on the API request.
    # * oauth_token: The access token or oauth token received on behalf of
    #                the user to make an authenticated request.
    # * oauth_token_secret: The supported secret value which has to be passed
    #                       to the request being made.
    # * use_header_auth: Does the request require a header to be passed?
    # * additional_params: Any additional parameter that can be passed
    #                      like `oauth_verifier`, `oauth_callback_url`, etc.
    def oauth1a(url_request,
                request_method = HTTP_METHOD_GET,
                oauth_token = '',
                oauth_token_secret = '',
                use_header_auth = false,
                additional_params = {})


      # Get the oauth params.
      oauth_params = get_oauth_params(oauth_token, additional_params)

      # Arrange the order of oauth params in alphabetical order.
      ordered_key = []
      oauth_params.keys.sort.each do |key|
        ordered_key << "#{percent_encode(key)}=#{percent_encode(oauth_params[key])}"
      end

      query_params = ordered_key.join('&')
      oauth_params['oauth_signature'] = create_signature(url_request,
                                                         request_method,
                                                         oauth_token_secret,
                                                         query_params)

      # Form headers if required.
      headers_payload = {}
      headers_payload = create_header(request_method, oauth_params) if use_header_auth

      # Form the request for making the REST call.
      opts = { :headers => headers_payload }
      payload = nil

      case request_method
      when HTTP_METHOD_GET
        url_request = "#{url_request}?#{query_params}"
      when HTTP_METHOD_POST
        payload = query_params.encode('ISO-8859-1')
      else
        raise('Invalid request_method passed for OAuth.')
      end

      begin
        execute_rest_request(url_request, request_method.downcase.to_sym, payload, opts)
      rescue RestClient::Exception => rest_error
        puts("Error Occurred in OAuth 1.0 Call. #{rest_error}")
        raise(rest_error)
      end
    end

    # Convert the string to a Percent encoding.
    # The new methods after URI.encode (Deprecated) don't convert `space` to `%20`
    # but instead convert them to `+`. For OAuth 1.0 use case, we can substitute `+` with `%20`.
    # Details here: https://developer.twitter.com/en/docs/authentication/oauth-1-0a/percent-encoding-parameters
    def percent_encode(plain_text)
      CGI.escape(plain_text).tr('+', '%20')
    end

    # Convert the query string to a hash.
    def to_hash(query_string)
      response_hash = {}

      arr_queries = query_string.split('&')
      arr_queries.each do |query|
        split_key_value = query.split('=')
        value = split_key_value[1]

        # Convert the String format `true` or `false` to a boolean true or false.
        if value && %w(true false).include?(value.to_s.downcase)
          value = value.to_s.downcase == 'true'
        end

        response_hash[split_key_value[0]] = value
      end

      response_hash
    end

    private

    # OAuth Parameter Constants.
    CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'.freeze
    OAUTH_SIGNATURE_METHOD       = 'HMAC-SHA1'.freeze
    OAUTH_1_VERSION              = '1.0'.freeze
    DIGEST_ALGO_SHA1             = 'sha1'.freeze
    HTTP_USER_AGENT              = 'HTTP Client'.freeze

    # Encode the string to Base64 Strict Encoding.
    def encode64(string)
      Base64.strict_encode64(string)
    end

    # Create the OAuth Parameters hash.
    def get_oauth_params(oauth_token, additional_params)
      # Create oauth_nonce by getting the time since epoch and
      # converting it to an alpha-numeric string.
      timestamp_float = Time.now.to_f
      oauth_nonce = encode64(timestamp_float.to_s.tr('.', ''))

      # Timestamp is the number of seconds from the epoch.
      oauth_timestamp = timestamp_float.to_i.to_s

      # Create Parameters for OAuth 1 request.
      oauth_params = {
        'oauth_consumer_key' => @consumer_key,
        'oauth_nonce' => oauth_nonce,
        'oauth_signature_method' => OAUTH_SIGNATURE_METHOD,
        'oauth_timestamp' => oauth_timestamp,
        'oauth_version' => OAUTH_1_VERSION
      }.merge(additional_params)

      oauth_params['oauth_token'] = oauth_token unless oauth_token.nil? || oauth_token.empty?
      oauth_params['api_key']     = @consumer_key

      # Return oauth_params hash.
      oauth_params
    end

    # Create Signature for OAuth 1.0.
    # * url_request: The request URL from where data has to be fetched from.
    # * request_method: HTTP GET/POST method.
    # * oauth_token_secret: Token Secret received from the external response.
    # * query_params: String of key-value pairs.
    def create_signature(url_request, request_method, oauth_token_secret, query_params)
      # OAuth Standard for signing key is [POST/GET]&url_request&parameter_in_alphabetical_order.
      message = [request_method, percent_encode(url_request), percent_encode(query_params)].join('&')

      # Create a HMAC-SHA1 signature of the message.
      sign_key = "#{percent_encode(@consumer_secret)}&#{percent_encode(oauth_token_secret)}"
      signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(DIGEST_ALGO_SHA1), sign_key, message)

      # Return Base64 encoded Signature.
      encode64(signature)
    end

    # Create the header payload for OAuth 1.0 request.
    def create_header(request_method, params)
      headers_payload = {}
      arr_header_payload = []

      # The header payload should be in the format percent_encode(key)=percent_encode("value").
      # The order of parameters should be lexicographically sorted.
      params.keys.sort.each do |key|
        arr_header_payload << "#{percent_encode(key)}=\"#{percent_encode(params[key])}\""
      end

      # For OAuth 1.0, the authorization header should start with `OAuth`.
      headers_str_payload = "OAuth #{arr_header_payload.join(', ')}"
      headers_payload['Authorization'] = headers_str_payload

      # If the request_method is POST, add the content type encoding.
      headers_payload['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED if request_method == HTTP_METHOD_POST

      # User Agent.
      headers_payload['User-Agent'] = HTTP_USER_AGENT

      # Return the header payload.
      headers_payload
    end

    # This method is used for making REST request calls.
    # Mandatory Parameters
    # * :url The external URL that needs to be accessed.
    # Optional Parameters
    # * :http_method The REST method to access the external api. Default is GET.
    # * :payload Pass the payload hash for the `POST`, `PUT` or `PATCH` HTTP requests.
    #     The hash values get serialized to query string for these HTTP requests.
    # * :opts Provide additional parameters that are required for making the REST call.
    def execute_rest_request(url, http_method = :get, payload = nil, opts = {})
      opts[:timeout] = 10 if opts[:timeout].nil?
      opts[:open_timeout] = 5 if opts[:open_timeout].nil?

      request = {
        :method => http_method,
        :url => url
      }.merge(opts)
      request[:payload] = payload if payload

      RestClient::Request.execute(request)
    end
end
