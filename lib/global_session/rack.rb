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

require File.expand_path(File.join(File.dirname(__FILE__), "..", "global_session"))

# Make sure the namespace exists, to satisfy Rails auto-loading
module GlobalSession
  module Rack
    # Global session middleware.  Note: this class relies on
    # Rack::Cookies being used higher up in the chain.
    class Middleware
      LOCAL_SESSION_KEY = "rack.session".freeze

      # Make a new global session.
      #
      # The optional block here controls an alternate ticket retrieval
      # method.  If no ticket is stored in the cookie jar, this
      # function is called.  If it returns a non-nil value, that value
      # is the ticket.
      #
      # === Parameters
      # app(Rack client): application to run
      # configuration(String or Configuration): global_session configuration.
      #                                         If a string, is interpreted as a
      #                                         filename to load the config from.
      # directory(String or Directory):         Directory object that provides
      #                                         trust services to the global
      #                                         session implementation. If a
      #                                         string, is interpreted as a
      #                                         filesystem directory containing
      #                                         the public and private keys of
      #                                         authorities, from which default
      #                                         trust services will be initialized.
      #
      # block: optional alternate ticket retrieval function
      def initialize(app, configuration, directory, &block)
        @app = app

        if configuration.instance_of?(String)
          @configuration = Configuration.new(configuration, ENV['RACK_ENV'] || 'development')
        else
          @configuration = configuration
        end

        begin
          klass_name = @configuration['directory'] || 'GlobalSession::Directory'

          #Constantize the type name that was given as a string
          parts = klass_name.split('::')
          namespace = Object
          namespace = namespace.const_get(parts.shift.to_sym) until parts.empty?
          directory_klass = namespace
        rescue Exception => e
          raise GlobalSession::ConfigurationError, "Invalid/unknown directory class name #{@configuration['directory']}"
        end

        if directory.instance_of?(String)
          @directory = directory_klass.new(@configuration, directory)
        else
          @directory = directory
        end

        @cookie_retrieval = block
        @cookie_name = @configuration['cookie']['name']
      end

      # Rack request chain. Sets up the global session ticket from
      # the environment and passes it up the chain.
      def call(env)
        env['rack.cookies'] = {} unless env['rack.cookies']

        begin
          err = nil
          read_authorization_header(env) || read_cookie(env) || create_session(env)
        rescue Exception => read_err
          err = read_err

          # Catch "double whammy" errors
          begin
            env['global_session'] = @directory.create_session
          rescue Exception => create_err
            err = create_err
          end

          handle_error('reading session cookie', env, err)
        end

        tuple = nil

        begin
          tuple = @app.call(env)
        rescue Exception => read_err
          handle_error('processing request', env, read_err)
          return tuple
        else
          renew_cookie(env)
          update_cookie(env)
          return tuple
        end
      end

      # Read a global session from the HTTP Authorization header, if present. If an authorization
      # header was found, also disable global session cookie update and renewal by setting the
      # corresponding keys of the Rack environment.
      #
      # === Parameters
      # env(Hash): Rack environment.
      #
      # === Return
      # result(true,false):: Returns true if the environment was populated, false otherwise
      def read_authorization_header(env)
        if env.has_key? 'X-HTTP_AUTHORIZATION'
          # RFC2617 style (preferred by OAuth 2.0 spec)
          header_data = env['X-HTTP_AUTHORIZATION'].to_s.split
        elsif env.has_key? 'HTTP_AUTHORIZATION'
          # Fallback style (generally when no load balancer is present, e.g. dev/test)
          header_data = env['HTTP_AUTHORIZATION'].to_s.split
        else
          header_data = nil
        end

        if header_data && header_data.size == 2 && header_data.first.downcase == 'bearer'
          env['global_session.req.renew'] = false
          env['global_session.req.update'] = false
          env['global_session'] = @directory.load_session(header_data.last)
          true
        else
          false
        end
      end

      # Read a global session from HTTP cookies, if present.
      #
      # === Parameters
      # env(Hash): Rack environment.
      #
      # === Return
      # result(true,false):: Returns true if the environment was populated, false otherwise
      def read_cookie(env)
        if @cookie_retrieval && (cookie = @cookie_retrieval.call(env))
          env['global_session'] = @directory.load_session(cookie)
          true
        elsif env['rack.cookies'].has_key?(@cookie_name)
          env['global_session'] = @directory.load_session(env['rack.cookies'][@cookie_name])
          true
        else
          false
        end
      end

      # Ensure that the Rack environment contains a global session object; create a session
      # if necessary.
      #
      # === Parameters
      # env(Hash): Rack environment.
      #
      # === Return
      # true:: always returns true
      def create_session(env)
        env['global_session'] ||= @directory.create_session

        true
      end

      # Renew the session ticket.
      #
      # === Parameters
      # env(Hash): Rack environment
      def renew_cookie(env)
        return unless @directory.local_authority_name
        return if env['global_session.req.renew'] == false

        if (renew = @configuration['renew']) && env['global_session'] &&
            env['global_session'].expired_at < Time.at(Time.now.utc + 60 * renew.to_i)
          env['global_session'].renew!
        end
      end

      # Update the cookie jar with the revised ticket.
      #
      # === Parameters
      # env(Hash): Rack environment
      def update_cookie(env)
        return unless @directory.local_authority_name
        return if env['global_session.req.update'] == false

        session = env['global_session']

        if session
          unless session.valid?
            old_session = session
            session = @directory.create_session
            perform_invalidation_callbacks(env, old_session, session)
            env['global_session'] = session
          end

          value = session.to_s
          expires = @configuration['ephemeral'] ? nil : session.expired_at
          unless env['rack.cookies'][@cookie_name] == value
            env['rack.cookies'][@cookie_name] =
                {:value => value,
                 :domain => cookie_domain(env),
                 :expires => expires,
                 :httponly=>true}
          end
        else
          # write an empty cookie
          wipe_cookie(env)
        end
      rescue Exception => e
        wipe_cookie(env)
        raise e
      end

      # Delete the global session cookie from the cookie jar.
      #
      # === Parameters
      # env(Hash): Rack environment
      def wipe_cookie(env)
        return unless @directory.local_authority_name
        return if env['global_session.req.update'] == false

        env['rack.cookies'][@cookie_name] = {:value => nil,
                                             :domain => cookie_domain(env),
                                             :expires => Time.at(0)}
      end

      # Handle exceptions that occur during app invocation. This will either save the error
      # in the Rack environment or raise it, depending on the type of error. The error may
      # also be logged.
      #
      # === Parameters
      # activity(String): name of activity in which error happened
      # env(Hash): Rack environment
      # e(Exception): error that happened
      def handle_error(activity, env, e)
        if env['rack.logger']
          msg = "#{e.class} while #{activity}: #{e}"
          msg += " #{e.backtrace}" unless e.is_a?(ExpiredSession)
          env['rack.logger'].error(msg)
        end

        if e.is_a?(ClientError) || e.is_a?(SecurityError)
          env['global_session.error'] = e
          wipe_cookie(env)
        elsif e.is_a? ConfigurationError
          env['global_session.error'] = e
        else
          raise e
        end
      end

      # Perform callbacks to directory and/or local session
      # informing them that this session has been invalidated.
      #
      # === Parameters
      # env(Hash):: the rack environment
      # old_session(GlobalSession):: the now-invalidated session
      # new_session(GlobalSession):: the new session that will be sent to the client
      def perform_invalidation_callbacks(env, old_session, new_session)
        if (local_session = env[LOCAL_SESSION_KEY]) && local_session.respond_to?(:rename!)
          local_session.rename!(old_session, new_session)
        end

        true
      end

      # Determine the domain name for which we should set the cookie. Uses the domain specified
      # in the configuration if one is found; otherwise, uses the SERVER_NAME from the request
      # but strips off the first component if the domain name contains more than two components.
      #
      # === Parameters
      # env(Hash):: the Rack environment hash
      def cookie_domain(env)
        if @configuration['cookie'].key?('domain')
          # Use the explicitly provided domain name
          domain = @configuration['cookie']['domain']
        else
          # Use the server name, but strip off the most specific component
          parts = env['SERVER_NAME'].split('.')
          parts = parts[1..-1] if parts.length > 2
          domain = parts.join('.')
        end

        domain
      end
    end
  end
end

module Rack
  GlobalSession = ::GlobalSession::Rack::Middleware unless defined?(::Rack::GlobalSession)
end
