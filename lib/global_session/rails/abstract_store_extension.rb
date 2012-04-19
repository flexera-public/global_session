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

module ActionController
  module Session
    class AbstractStore

      # This method override AbstractStore#call
      # We don't need to store rails session id in cookies and don't care about expiration.
      alias_method :call_original, :call
      def call(env)
        session = SessionHash.new(self, env)

        env[ENV_SESSION_KEY] = session
        env[ENV_SESSION_OPTIONS_KEY] = @default_options.dup

        response = @app.call(env)

        session_data = env[ENV_SESSION_KEY]

        if !session_data.is_a?(AbstractStore::SessionHash) || session_data.send(:loaded?)
          session_data.send(:load!) if session_data.is_a?(AbstractStore::SessionHash) && !session_data.send(:loaded?)
          set_session(env, env['global_session'].id, session_data.to_hash)
        end

        response
      end

      private

      # This method override AbstractStore#load_session.
      # We use GlobalSession#id as rails session id.
      alias_method :load_session_original, :load_session
      def load_session(env)
        sid = env['global_session'].id
        unless @cookie_only
          sid ||= request.params[@key]
        end
        sid, session = get_session(env, sid)
        [sid, session]
      end

    end
  end
end
