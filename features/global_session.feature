Feature: GlobalSession
  In order to test default behavior for global_session
  I want to duplicate some rspec scenarios here

  Background:
    Given a keystore
    And the following keys in my keystore:
      | authority1 | true   |
      | authority2 | false  |
    And I have the following mock_configs:
      | common/attributes/signed    | ['user']            |
      | common/attributes/insecure  | ['favorite_color']  |
      | test/timeout                | '60'                |
      | test/trust                  | ['authority1']      |
      | test/authority              | 'authority1'        |

  Scenario: everything is copacetic
    Given a valid global session cookie
    Then everything is ok

  Scenario: changing insecure attributes
    Given a valid global session cookie
    And an insecure attribute has changed
    Then everything is ok
