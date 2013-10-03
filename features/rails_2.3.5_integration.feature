Feature: Rails 2.3.5 integration
  In order to ensure full compatibility with different Rails versions
  Developers can use global_session with Rails 2.3.5

  Background:
    Given a Rails 2.3.5 application
    And I use development environment
    And I use localhost as a domain
    And the app is configured to use global_session
    And a database
    And the global_session gem is available

  Scenario: configuring global_session middleware
    Given global_session added as a middleware
    When I launch my application
    Then I should have my application up and running

  Scenario: initializing global_session cookies
    When I send a GET request to 'happy/index'
    Then I should receive a message "Be Happy!!!"
    And I have 2 cookies named:
      | global_session |
      | _local_session |

  Scenario: save data to the local session
    When I send a POST request to 'happy/update' with parameters:
      | key   | my_data       |
      | value | hello cookies |
    Then I should be redirected to 'happy/index'
    And I should receive in session the following variables:
      | my_data | hello cookies |
    And I have 2 cookies named:
      | global_session |
      | _local_session |

  Scenario: retrieve data from the local session
    Given I have a local session with data:
      | woohoo | yabadabadoo |
    When I send a GET request to 'happy/index'
    And I should receive in session the following variables:
      | woohoo | yabadabadoo |

  Scenario: delete data from the local sessoin
    Given I have a local session with data:
      | woohoo  | yabadabadoo   |
      | my_data | hello cookies |
    When I send a DELETE request to 'happy/destroy' with parameters:
      | key | woohoo |
    Then I should be redirected to 'happy/index'
    And I should receive in session the following variables:
      | my_data | hello cookies |

  Scenario: expired global_session
    Given I have a local session with data:
      | woohoo | yabadabadoo |
    And I have an expired global session
    When I send a GET request to 'happy/index'
    Then I should receive empty session
    And I should have new global_session generated

