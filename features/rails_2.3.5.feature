Feature: Rails 2.3.5
  In order to ensure full compatibility with different Rails versions
  Developers should be able to use global_session for Rails 2.3.5

  Scenario:
    Given a Rails 2.3.5 application
    And configuration fixtures are loaded
    And database created
    And global_session added as a gem

  Scenario: configuring global_session authority
    Given I use development environment
    When I run './script/generate' with 'global_session_authority'
    Then I should receive message about about successful result
    And I should have the following files generated:
      | config | authorities | development.key |
      | config | authorities | development.pub |

  Scenario: configuring global_session config
    Given I use localhost as a domain
    When I run './script/generate' with 'global_session'
    Then I should receive message about successful result
    And I should have the following files generated:
      | config | global_session.yml |

  Scenario: configuring global_session middleware
    Given global_session added as a middleware
    When I lunch my application on 11415 port
    Then I should have my application up and running

  Scenario: initializing global_session cookies
    When I send GET request 'happy/index'
    Then I should receive message "Be Happy!!!"
    And I have 2 cookie variable called:
      | global_session |
      | _local_session |

  Scenario: save data to the local session
    When I send POST request 'happy/update' with the following:
      | key   | my_data       |
      | value | hello cookies |
    Then I should be redirected to 'happy/index'
    And I should receive in session the following variables:
      | my_data | hello cookies |
    And I have 2 cookie variable called:
      | global_session |
      | _local_session |

  Scenario: local session integration
    Given global_session configured with local session integration
    When I send GET request 'happy/index'
    Then I should receive message "Be Happy!!!"
    And I have 1 cookie variable called:
      | global_session |

  Scenario: save data to the local session
    When I send POST request 'happy/update' with the following:
      | key   | my_data       |
      | value | hello cookies |
    Then I should be redirected to 'happy/index'
    And I should receive in session the following variables:
      | my_data | hello cookies |
    And I have 1 cookie variable called:
      | global_session |

  Scenario: retrieve data from the local session
    Given I have data stored in local session:
      | woohoo | yabadabadoo |
    When I send GET request 'happy/index'
    And I should receive in session the following variables:
      | woohoo | yabadabadoo |

  Scenario: delete data from the local sessoin
    Given I have data stored in local session:
      | woohoo  | yabadabadoo   |
      | my_data | hello cookies |
    When I send DELETE request 'happy/destroy' with the following:
      | key | woohoo |
    Then I should be redirected to 'happy/index'
    And I should receive in session the following variables:
      | my_data | hello cookies |

  Scenario: expired global_session
    Given I have data stored in local session:
      | woohoo | yabadabadoo |
    And I have global_session expired
    When I send GET request 'happy/index'
    Then I should receive empty session
    And I should have new global_session generated

