# Compile support files
Code.require_file("support/test_helpers.ex", __DIR__)
Code.require_file("support/query_helpers.ex", __DIR__)

# Exclude slow tests by default (run with: mix test --include slow)
ExUnit.start(exclude: [:slow])
