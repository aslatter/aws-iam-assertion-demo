This program is a demo of using pre-signed STS 'GetCallerIdentity' requests
to act as an IAM-identity-assertion to some third-party identity-provider.

The client:
- signs an STS request, including a custom "audience" header

The issuer:
- receives the signed STS request
- validates the URL endpoint
- invokes the pre-signed request
- validates the returned identity-ARN

This function is a sketch of the key parts - specifically
the generation of the pre-signed request and the invoking
of the pre-signed request (including a custom header).

Inspired by:
- https://developer.hashicorp.com/vault/docs/auth/aws (https://web.archive.org/web/20240425083125/https://developer.hashicorp.com/vault/docs/auth/aws)
- Discovered via: https://www.reddit.com/r/aws/comments/7p90lv/can_i_use_iam_to_authenticate_calls_to_my_own/dsfih0r/ (https://web.archive.org/web/20240811164120/https://old.reddit.com/r/aws/comments/7p90lv/can_i_use_iam_to_authenticate_calls_to_my_own/dsfih0r/)
