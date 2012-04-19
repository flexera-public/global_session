ActionController::Base.session = {
  :key         => '_local_session',
  :secret      => 'f9459ef5b24e84afeae24599913fb10d77ad90bd0207f86ecdc23d619d8e411de6f3029f412990b6a55852dcbe2aa4030c4e41f2a8783562f51124617fdfb341'
}
ActionController::Base.session_store = :active_record_store
