module GlobalSession
  module Session
  end
end

require 'global_session/session/abstract'
require 'global_session/session/v1'
require 'global_session/session/v2'

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
  def self.decode_cookie(*args)
    V2.decode_cookie(*args)
  rescue GlobalSession::MalformedCookie => e
    V1.decode_cookie(*args)
  end

  def self.new(directory, cookie=nil, valid_signature_digest=nil)
    V2.new(directory, cookie)
  rescue GlobalSession::MalformedCookie => e
    V1.new(directory, cookie, valid_signature_digest)
  end
end
