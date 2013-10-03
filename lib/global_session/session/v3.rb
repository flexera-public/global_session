# Copyright (c) 2012 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Standard library dependencies
require 'set'

module GlobalSession::Session
  # Global session V3 uses JSON serialization, no compression, and a detached signature that is
  # excluded from the JSON structure for efficiency reasons.
  #
  # The binary structure of a V3 session looks like this:
  #  <utf8_json><0x00><binary_signature>
  #
  # Its JSON structure is an Array with the following format:
  #  [<version_integer>,
  #   <uuid_string>,
  #   <signing_authority_string>,
  #   <creation_timestamp_integer>,
  #   <expiration_timestamp_integer>,
  #   {<signed_data_hash>},
  #   {<unsigned_data_hash>}]
  #
  # The design goal of V3 is to ensure broad compatibility across various programming languages
  # and cryptographic libraries, and to create a serialization format that can be reused for
  # future versions. To this end, it sacrifices space efficiency by switching back to JSON
  # encoding (instead of msgpack), and uses the undocumented OpenSSL::PKey#sign and #verify
  # operations which rely on the PKCS7-compliant OpenSSL EVP API.
  class V3 < Abstract
    STRING_ENCODING = !!(RUBY_VERSION !~ /1.8/)

    # Utility method to decode a cookie; good for console debugging. This performs no
    # validation or security check of any sort.
    #
    # === Parameters
    # cookie(String):: well-formed global session cookie
    def self.decode_cookie(cookie)
      bin = GlobalSession::Encoding::Base64Cookie.load(cookie)
      json, sig = split_body(bin)
      return GlobalSession::Encoding::JSON.load(json), sig
    end

    # Split an ASCII-8bit input string into two constituent parts: a UTF-8 JSON document
    # and an ASCII-8bit binary string. A null (0x00) separator character is presumed to
    # separate the two parts of the input string.
    #
    # This is an implementation helper for GlobalSession serialization and not useful for
    # the public at large. It's left public as an aid for those who want to hack sessions.
    #
    # @param [String] input a binary string (encoding will be forced to ASCII_8BIT!)
    # @return [Array] returns a 2-element Array of String: json document, plus binary signature
    # @raise [ArgumentError] if the null separator is missing
    def self.split_body(input)
      input.force_encoding(Encoding::ASCII_8BIT) if STRING_ENCODING
      null_at = input.index("\x00")

      if null_at
        json = input[0...null_at]
        sig = input[null_at+1..-1]
        if STRING_ENCODING
          json.force_encoding(Encoding::UTF_8)
          sig.force_encoding(Encoding::ASCII_8BIT)
        end

        return json, sig
      else
        raise ArgumentError, "Malformed input string does not contain 0x00 byte"
      end
    end

    # Join a UTF-8 JSON document and an ASCII-8bit binary string.
    #
    # This is an implementation helper for GlobalSession serialization and not useful for
    # the public at large. It's left public as an aid for those who want to hack sessions.
    #
    # @param [String] json a UTF-8 JSON document (encoding will be forced to UTF_8!)
    # @param [String] signature a binary signautre (encoding will be forced to ASCII_8BIT!)
    # @return [String] a binary concatenation of the two inputs, separated by 0x00
    def self.join_body(json, signature)
      result = ""
      if STRING_ENCODING
        result.force_encoding(Encoding::ASCII_8BIT)
        json.force_encoding(Encoding::ASCII_8BIT)
        signature.force_encoding(Encoding::ASCII_8BIT)
      end

      result << json
      result << "\x00"
      result << signature
      result
    end


    # Serialize the session to a form suitable for use with HTTP cookies. If any
    # secure attributes have changed since the session was instantiated, compute
    # a fresh RSA signature.
    #
    # === Return
    # cookie(String):: The B64cookie-encoded JSON-serialized global session
    def to_s
      if @cookie && !@dirty_insecure && !@dirty_secure
        #use cached cookie if nothing has changed
        return @cookie
      end

      hash = {'v' => 3,
              'id' => @id, 'a' => @authority,
              'tc' => @created_at.to_i, 'te' => @expired_at.to_i,
              'ds' => @signed}

      if @signature && !@dirty_secure
        #use cached signature unless we've changed secure state
        authority = @authority
      else
        authority_check
        authority = @directory.local_authority_name
        hash['a'] = authority
        signed_hash = RightSupport::Crypto::SignedHash.new(
          hash,
          :envelope=>true,
          :encoding=>GlobalSession::Encoding::JSON,
          :private_key=>@directory.private_key)
        @signature = signed_hash.sign(@expired_at)
      end

      hash['dx'] = @insecure
      hash['a'] = authority

      array = attribute_hash_to_array(hash)
      json = GlobalSession::Encoding::JSON.dump(array)
      bin = self.class.join_body(json, @signature)
      return GlobalSession::Encoding::Base64Cookie.dump(bin)
    end

    # Return the keys that are currently present in the global session.
    #
    # === Return
    # keys(Array):: List of keys contained in the global session
    def keys
      @signed.keys + @insecure.keys
    end

    # Return the values that are currently present in the global session.
    #
    # === Return
    # values(Array):: List of values contained in the global session
    def values
      @signed.values + @insecure.values
    end

    # Iterate over each key/value pair
    #
    # === Block
    # An iterator which will be called with each key/value pair
    #
    # === Return
    # Returns the value of the last expression evaluated by the block
    def each_pair(&block) # :yields: |key, value|
      @signed.each_pair(&block)
      @insecure.each_pair(&block)
    end

    # Lookup a value by its key.
    #
    # === Parameters
    # key(String):: the key
    #
    # === Return
    # value(Object):: The value associated with +key+, or nil if +key+ is not present
    def [](key)
      key = key.to_s #take care of symbol-style keys
      @signed[key] || @insecure[key]
    end

    # Set a value in the global session hash. If the supplied key is denoted as
    # secure by the global session schema, causes a new signature to be computed
    # when the session is next serialized.
    #
    # === Parameters
    # key(String):: The key to set
    # value(Object):: The value to set
    #
    # === Return
    # value(Object):: Always returns the value that was set
    #
    # ===Raise
    # InvalidSession:: if the session has been invalidated (and therefore can't be written to)
    # ArgumentError:: if the configuration doesn't define the specified key as part of the global session
    # NoAuthority:: if the specified key is secure and the local node is not an authority
    # UnserializableType:: if the specified value can't be serialized as JSON
    def []=(key, value)
      key = key.to_s #take care of symbol-style keys
      raise GlobalSession::InvalidSession unless valid?

      if @schema_signed.include?(key)
        authority_check
        @signed[key] = value
        @dirty_secure = true
      elsif @schema_insecure.include?(key)
        @insecure[key] = value
        @dirty_insecure = true
      else
        raise ArgumentError, "Attribute '#{key}' is not specified in global session configuration"
      end

      return value
    end

    # Renews this global session, changing its expiry timestamp into the future.
    # Causes a new signature will be computed when the session is next serialized.
    #
    # === Return
    # true:: Always returns true
    def renew!(expired_at=nil)
      super(expired_at)
      @dirty_secure = true
    end

    # Return the SHA1 hash of the most recently-computed RSA signature of this session.
    # This isn't really intended for the end user; it exists so the Web framework integration
    # code can optimize request speed by caching the most recently verified signature in the
    # local session and avoid re-verifying it on every request.
    #
    # === Return
    # digest(String):: SHA1 hex-digest of most-recently-computed signature
    def signature_digest
      @signature ? digest(@signature) : nil
    end

    private

    def load_from_cookie(cookie) # :nodoc:
      hash = nil

      begin
        array, signature = self.class.decode_cookie(cookie)
        hash = attribute_array_to_hash(array)
      rescue Exception => e
        mc = GlobalSession::MalformedCookie.new("Caused by #{e.class.name}: #{e.message}")
        mc.set_backtrace(e.backtrace)
        raise mc
      end

      _ = hash['v']
      id = hash['id']
      authority = hash['a']
      created_at = Time.at(hash['tc'].to_i).utc
      expired_at = Time.at(hash['te'].to_i).utc
      signed = hash['ds']
      insecure = hash.delete('dx')

      #Check trust in signing authority
      if @directory.trusted_authority?(authority)
        signed_hash = RightSupport::Crypto::SignedHash.new(
          hash,
          :envelope=>true,
          :encoding=>GlobalSession::Encoding::JSON,
          :public_key=>@directory.authorities[authority])

        begin
          signed_hash.verify!(signature, expired_at)
        rescue RightSupport::Crypto::ExpiredSignature
          raise GlobalSession::ExpiredSession, "Session expired at #{expired_at}"
        rescue RightSupport::Crypto::InvalidSignature => e
          raise SecurityError, "Global session signature verification failed: " + e.message
        end

      else
        raise SecurityError, "Global sessions signed by #{authority.inspect} are not trusted"
      end

      #Check expiration
      unless expired_at > Time.now.utc
        raise GlobalSession::ExpiredSession, "Session expired at #{expired_at}"
      end

      #Check other validity (delegate to directory)
      unless @directory.valid_session?(id, expired_at)
        raise GlobalSession::InvalidSession, "Global session has been invalidated"
      end

      #If all validation stuff passed, assign our instance variables.
      @id = id
      @authority = authority
      @created_at = created_at
      @expired_at = expired_at
      @signed = signed
      @insecure = insecure
      @signature = signature
      @cookie = cookie
    end

    def create_from_scratch # :nodoc:
      authority_check

      @signed = {}
      @insecure = {}
      @created_at = Time.now.utc
      @authority = @directory.local_authority_name
      @id = RightSupport::Data::UUID.generate
      renew!
    end

    def create_invalid # :nodoc:
      @id = nil
      @created_at = Time.now.utc
      @expired_at = created_at
      @signed = {}
      @insecure = {}
      @authority = nil
    end

    # Transform a V1-style attribute hash to an Array with fixed placement for
    # each element. The V3 scheme is serialized as an array to save space.
    #
    # === Parameters
    # hash(Hash):: the attribute hash
    #
    # === Return
    # attributes(Array)::
    #
    def attribute_hash_to_array(hash)
      [
        hash['v'],
        hash['id'],
        hash['a'],
        hash['tc'],
        hash['te'],
        hash['ds'],
        hash['dx'],
      ]
    end

    # Transform a V2-style attribute array to a Hash with the traditional attribute
    # names. This is good for passing to SignedHash, or initializing a V1 session for
    # downrev compatibility.
    #
    # === Parameters
    # hash(Hash):: the attribute hash
    #
    # === Return
    # attributes(Array):: fixed-position attributes array
    #
    def attribute_array_to_hash(array)
      {
        'v'  => array[0],
        'id' => array[1],
        'a'  => array[2],
        'tc' => array[3],
        'te' => array[4],
        'ds' => array[5],
        'dx' => array[6],
      }
    end
  end
end
