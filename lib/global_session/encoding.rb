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

# Standard library (or possibly gem) dependencies
require 'json'

begin
  require 'msgpack'
rescue LoadError => e
  # Msgpack is optional (only required for V2 session support)
end

module GlobalSession
  # Various encoding (not encryption!) techniques used by the global session plugin.
  #
  module Encoding
    # JSON serializer, used to serialize Hash objects in a form suitable
    # for stuffing into a cookie.
    #
    # Note that the #load method does not have the serialization semantics of the
    # Marshal/YAML load/dump interface; any embedded Ruby objects will remain in
    # their hash-serialized form. (Global session contents are not trustworthy enough
    # to allow Ruby object serialization.)
    module JSON
      # Unserialize JSON to Hash.
      #
      # === Parameters
      # json(String):: A well-formed JSON document
      #
      # === Return
      # value(Hash):: An unserialized Ruby Hash
      def self.load(json)
        ::JSON.parse(json)
      end

      # Serialize Hash to JSON document.
      #
      # === Parameters
      # value(Hash):: The hash to be serialized
      #
      # === Return
      # json(String):: A JSON-serialized representation of +value+
      def self.dump(object)
        return ::JSON.dump(object)
      end
    end

    # Wrapper module for MessagePack that makes it conform to the standard load/dump interface
    # for serializers.
    module Msgpack
      def self.load(binary)
        if defined?(MessagePack)
          MessagePack.unpack(binary)
        else
          raise NotImplementedError, "::MessagePack undefined; please install 'msgpack' gem to enable this optional functionality"
        end
      end

      def self.dump(object)
        if object.respond_to?(:to_msgpack)
          object.to_msgpack
        else
          raise NotImplementedError, "#to_msgpack unavailable; please install 'msgpack' gem to enable this optional functionality"
        end
      end
    end

    # Implements URL encoding, but without newlines, and using '-' and '_' as
    # the 62nd and 63rd symbol instead of '+' and '/'. This makes for encoded
    # values that can be easily stored in a cookie; however, they cannot
    # be used in a URL query string without URL-escaping them since they
    # will contain '=' characters.
    #
    # This scheme is almost identical to the scheme "Base 64 Encoding with URL
    # and Filename Safe Alphabet," described in RFC4648, with the exception that
    # this scheme preserves the '=' padding characters due to limitations of
    # Ruby's built-in base64 encoding routines.
    class Base64Cookie
      # Decode a B64cookie-encoded string.
      #
      # === Parameters
      # encoded(String):: The encoded string
      #
      # === Return
      # decoded(String):: The decoded result, which may contain nonprintable bytes
      def self.load(string)
        tr = string.tr('-_', '+/')
        return tr.unpack('m')[0]
      end
      
      # Encode a Ruby (ASCII or binary) string.
      #
      # === Parameters
      # decoded(String):: The raw string to be encoded
      #
      # === Return
      # encoded(String):: The B64cookie-encoded result.
      def self.dump(object)
        raw = [object].pack('m')
        raw.tr!('+/', '-_')
        raw.gsub!("\n", '')
        return raw
      end
    end
  end
end
