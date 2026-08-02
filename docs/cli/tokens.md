# API Tokens

Bindizr uses API tokens for HTTP API authentication. You can manage these tokens
using the following commands:

```bash
# Create a new API token
$ bindizr token create --description "API access for monitoring"

# Create a token with expiration
$ bindizr token create --description "Temporary access" --expires-in-days 30

# List all API tokens
$ bindizr token list

# Delete an API token by ID
$ bindizr token delete <TOKEN_ID>

# Show token command help
$ bindizr token --help
```

See [HTTP API](../http-api/index.md#authentication) for how to present a token
on a request.
