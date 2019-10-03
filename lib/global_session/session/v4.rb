require 'securerandom'

module GlobalSession::Session
  # Version 4 is based on JSON Web Token; in fact, if there is no insecure
  # state, then a V4 session _is_ a JWT. Otherwise, it's a JWT with a
  # nonstandard fourth component containing the insecure state.
  class V4 < Abstract
    EXPIRED_AT = 'exp'.freeze
    ID         = 'id'.freeze
    ISSUED_AT  = 'iat'.freeze
    ISSUER     = 'iss'.freeze
    NOT_BEFORE = 'nbf'.freeze
    KEY_ID     = 'kid'.freeze

    # Pattern that matches possible Flexera Okta issuers
    ISSUER_REGEXP = /^https:\/\/secure.flexeratest.com|^https:\/\/secure.flexera.com/

    # Pattern that matches strings that are probably a V4 session cookie.
    HEADER = /^eyJ/

    def self.decode_cookie(cookie)
      header, payload, sig, insec = cookie.split('.')
      header, payload, insec = [header, payload, insec].
        map { |c| c && RightSupport::Data::Base64URL.decode(c) }.
        map { |j| j && GlobalSession::Encoding::JSON.load(j) }
      sig = sig && RightSupport::Data::Base64URL.decode(sig)
      insec ||= {}

      unless Hash === header
        raise GlobalSession::MalformedCookie, "JWT header unexpected format"
      end
      # typ header is optional, so only check if present
      if header['typ'] != nil && header['typ'] != 'JWT'
        raise GlobalSession::MalformedCookie, "Token type is not JWT"
      end

      unless Hash === payload
        raise GlobalSession::MalformedCookie, "JWT payload not present"
      end

      [header, payload, sig, insec]
    rescue JSON::ParserError => e
      raise GlobalSession::MalformedCookie, e.message
    end

    # Serialize the session. If any secure attributes have changed since the
    # session was instantiated, compute a fresh RSA signature.
    #
    # @return [String]
    def to_s
      if @cookie && !dirty?
        # nothing has changed; just return cached cookie
        return @cookie
      end

      unless @insecure.nil? || @insecure.empty?
        insec = GlobalSession::Encoding::JSON.dump(@insecure)
        insec = RightSupport::Data::Base64URL.encode(insec)
      end

      if @signature && !(@dirty_timestamps || @dirty_secure)
        # secure state hasn't changed; reuse JWT piece of cookie
        jwt = @cookie.split('.')[0..2].join('.')
      else
        # secure state has changed; recompute signature & make new JWT
        authority_check

        payload = @signed.dup
        payload[ID] = id
        payload[EXPIRED_AT] = @expired_at.to_i
        payload[ISSUED_AT] = @created_at.to_i
        payload[ISSUER] = @directory.local_authority_name

        sh = RightSupport::Crypto::SignedHash.new(payload, @directory.private_key, envelope: :jwt)
        jwt = sh.to_jwt(@expired_at)
      end

      if insec && !insec.empty?
        return "#{jwt}.#{insec}"
      else
        return jwt
      end
    end

    private

    def load_from_cookie(cookie)
      # Get the basic facts
      header, payload, sig, insec = self.class.decode_cookie(cookie)
      id         = payload[ID]
      created_at = payload[ISSUED_AT]
      issuer     = payload[ISSUER]
      expired_at = payload[EXPIRED_AT]
      not_before = payload[NOT_BEFORE]
      raise GlobalSession::InvalidSignature, "JWT iat claim missing/wrong" unless Integer === created_at
      raise GlobalSession::InvalidSignature, "JWT iat claim missing/wrong" unless Integer === expired_at
      created_at = Time.at(created_at)
      expired_at = Time.at(expired_at)
      if Numeric === not_before
        not_before = Time.at(not_before)
        raise GlobalSession::PrematureSession, "Session not valid before #{not_before}" unless Time.now >= not_before
      end

      # if this token was issued by Flexera IAM, we will use the "kid" header as the issuer
      if header[KEY_ID] && issuer =~ ISSUER_REGEXP
        issuer = header[KEY_ID]
      end

      # Check trust in signing authority
      if @directory.trusted_authority?(issuer)
        # Verify the signature
        key = @directory.authorities[issuer]
        digest_klass = digest_for_key(key)
        plaintext = cookie.split('.')[0..1].join('.')
        if key.respond_to?(:dsa_verify_asn1)
          # DSA signature with JWT-compatible encoding
          digest = digest_klass.new.update(plaintext).digest
          signature = raw_to_asn1(sig, key)
          result = key.dsa_verify_asn1(digest, signature)
          raise GlobalSession::InvalidSignature, "Global session signature verification failed: Signature mismatch: DSA verify failed" unless result
        elsif key.respond_to?(:verify)
          digest = digest_klass.new
          result = key.verify(digest, sig, plaintext)
          raise GlobalSession::InvalidSignature, "Global session signature verification failed: Signature mismatch: verify failed" unless result
        else
          raise NotImplementedError, "Cannot verify JWT with #{key.class.name}"
        end
        # Check expiration
        raise GlobalSession::ExpiredSession, "Session expired at #{expired_at}" unless expired_at >= Time.now
      else
        raise GlobalSession::InvalidSignature, "Global sessions signed by #{authority.inspect} are not trusted"
      end

      #Check other validity (delegate to directory)
      unless @directory.valid_session?(id, expired_at)
        raise GlobalSession::InvalidSession, "Global session has been invalidated"
      end

      #If all validation stuff passed, assign our instance variables.
      @id = id
      @authority = issuer
      @created_at = created_at
      @expired_at = expired_at
      @signed = payload
      @insecure = insec
      @signature = sig
      @cookie = cookie
    end

    # Returns the digest class used for the given key type
    #
    # @param key [OpenSSL::PKey::PKey] the key used for verifying signatures
    #
    # @return [OpenSSL::Digest] the digest class to use
    def digest_for_key(key)
      case key
      when OpenSSL::PKey::DSA
        OpenSSL::Digest::SHA1
      when OpenSSL::PKey::EC
        case key.group.degree
        when 256 then OpenSSL::Digest::SHA256
        when 384 then OpenSSL::Digest::SHA384
        when 521 then OpenSSL::Digest::SHA512
        else
          raise ArgumentError, "Cannot guess digest"
        end
      when OpenSSL::PKey::RSA
        OpenSSL::Digest::SHA256
      else
        OpenSSL::Digest::SHA1
      end
    end

    # Convert raw pair of concatenated bignums into ASN1-encoded pair of integers.
    # This only works for OpenSSL::PKey::EC.
    # https://github.com/jwt/ruby-jwt/blob/master/lib/jwt.rb#L159
    def raw_to_asn1(signature, public_key) # :nodoc:
      byte_size = (public_key.group.degree + 7) / 8
      r = signature[0..(byte_size - 1)]
      s = signature[byte_size..-1] || ''
      OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end

    def create_from_scratch
      @signed = {}
      @insecure = {}
      @created_at = Time.now.utc
      @authority = @directory.local_authority_name
      @id = generate_id
      renew!
    end
  end
end
