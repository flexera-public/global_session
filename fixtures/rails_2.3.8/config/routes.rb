ActionController::Routing::Routes.draw do |map|
  map.index  'happy/index', :controller => 'happy', :action => 'index'
  map.update 'happy/update', :controller => 'happy', :action => 'update'
  map.remove 'happy/destroy/:id', :controller => 'happy', :action => 'destroy'
end
