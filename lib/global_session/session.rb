module GlobalSession
  module Session
  end
end

require 'global_session/session/abstract'
require 'global_session/session/v1'
require 'global_session/session/v2'
require 'global_session/session/v3'
require 'global_session/session/v4'

# Ladies and gentlemen: the one and only, star of the show, GLOBAL SESSION!
#
# Session is designed to act as much like a Hash as possible. You can use
# most of the methods you would use with Hash: [], has_key?, each, etc. It has a
# few additional methods that are specific to itself, mostly involving whether
# it's expired, valid, supports a certain key, etc.
#
# Global sessions are versioned, and each version may have its own encoding
# strategy. This module acts as a namespace for the different versions, each
# of which is represented by a class in the module. They all inherit
# from the abstract base class in order to ensure that they are internally
# compatible with other components of this gem.
#
# This module also acts as a façade for reading global session cookies generated
# by the different versions; it is responsible for detecting the version of
# a given cookie, then instantiating a suitable session object.
module GlobalSession::Session
  # Decode a global session cookie without checking signature or expiration. Good for debugging.
  def self.decode_cookie(cookie)
    guess_version(cookie).decode_cookie(cookie)
  end

  # Decode a global session cookie. Use a heuristic to determine the version.
  # @raise [GlobalSession::MalformedCookie] if the cookie is not a valid serialized global session
  def self.new(directory, cookie=nil)
    guess_version(cookie).new(directory, cookie)
  end

  # Figure out the protocol version of a serialized session cookie.
  #
  # @param [String] cookie
  # @return [Class] implementation class that can probably deserialize cookie
  def self.guess_version(cookie)
    case cookie
    when V4::HEADER
      V4
    when nil, V3::HEADER
      V3
    when V2::HEADER
      V2
    else
      V1 # due to zlib compression, no foolproof way to spot V1 sessoins
    end
  end
end
