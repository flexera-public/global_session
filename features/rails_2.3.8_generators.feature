Feature: Rails 2.3.8 generators
  In order to ensure full compatibility with different Rails versions
  Developers can use global_session with Rails 2.3.8

  Background:
    Given a Rails 2.3.8 application
    And I use development environment
    And I use localhost as a domain
    And a database
    And the global_session gem is available

  Scenario: configuring global_session authority
    When I run './script/generate' with 'global_session_authority'
    Then I should receive a message about about successful result
    And my app should have the following files::
      | config | authorities | development.key |
      | config | authorities | development.pub |

  Scenario: configuring global_session config
    When I run './script/generate' with 'global_session'
    Then I should receive a message about successful result
    And my app should have the following files::
      | config | global_session.yml |
