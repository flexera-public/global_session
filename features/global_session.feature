Feature: GlobalSession
  In order to test default behaviour for global_session
  I want to duplicate some rspec scenarios here

  Background:
    Given a KeyFactory is on
    And I have the following keystores:
      | authority1 | true   |
      | authority2 | false  |
    And I have the following mock_configs:
      | common/attributes/signed    | ['user']            |
      | common/attributes/insecure  | ['favorite_color']  |
      | test/timeout                | '60'                |
      | test/trust                  | ['authority1']      |
      | test/authority              | 'authority1'        |

  Scenario: everything is copascetic
    When I load it from cookie successful
    Then everything is ok

  Scenario: a trusted signature
    When I load it from cookie successful
    And a trusted signature is passed in
    And I have a valid digest
    Then I should not recompute the signature

  Scenario: an insecure attribute
    When I load it from cookie successful
    And an insecure attribute has changed
    Then everything is ok
