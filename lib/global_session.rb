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

module GlobalSession
  # Indicates that the global session configuration file is malformatted or missing
  # required fields. Also used as a base class for other errors.
  class ConfigurationError < Exception; end

  # The general category of client-side errors. Used solely as a base class.
  class ClientError < Exception; end

  # Indicates that the global session configuration file is missing from disk.
  #
  class MissingConfiguration < ConfigurationError; end

  # Indicates that a client submitted a request with a valid session cookie, but the
  # session ID was reported as invalid by the Directory.
  #
  # See Directory#valid_session? for more information.
  #
  class InvalidSession < ClientError; end

  # Indicates that a client submitted a request with a valid session cookie, but the
  # session has expired.
  #
  class ExpiredSession < ClientError; end

  # Indicates that a client submitted a request with a session cookie that could not
  # be decoded or decompressed.
  #
  class MalformedCookie < ClientError; end

  # Indicates that application code tried to put an unserializable object into the glboal
  # session hash. Because the global session is serialized as JSON and not all Ruby types
  # can be easily round-tripped to JSON and back without data loss, we constrain the types
  # that can be serialized.
  #
  # See GlobalSession::Encoding::JSON for more information on serializable types.
  #
  class UnserializableType < ConfigurationError; end

  # Indicates that the application code tried to write a secure session attribute or
  # renew the global session. Both of these operations require a local authority
  # because they require a new signature to be computed on the global session.
  #
  # See GlobalSession::Configuration and GlobalSession::Directory for more
  # information.
  #
  class NoAuthority < ConfigurationError; end
end

#Make sure gem dependencies are activated.
require 'right_support'
require 'json'

#Require Ruby library dependencies
require 'openssl'

#Require the core suite of GlobalSession classes and modules
require 'global_session/configuration'
require 'global_session/directory'
require 'global_session/encoding'
require 'global_session/session'

#Preemptively try to activate the Rails plugin
if require_succeeds?('action_pack') && require_succeeds?('action_controller')
  require 'global_session/rails'
end
