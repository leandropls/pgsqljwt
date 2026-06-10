# JWT Decoder Functions for PostgreSQL

## Overview
Row-level security (RLS) in PostgreSQL is a feature that enables the restriction of database records visibility and access based on the current user's permissions. Instead of relying on application-level security, RLS enforces access control directly at the database level for each query, which allows for more granular and robust data protection.

By integrating JSON Web Tokens (JWTs) with RLS, PostgreSQL can authenticate users and apply access control policies using the information within the JWTs. This ensures that only the appropriate data is accessible to authenticated users based on their credentials. Verifying JWTs at the database level enhances overall security by preventing unauthorized access due to potential vulnerabilities in the application layer, centralizing critical access control logic within the database itself.

While PostgreSQL is a powerhouse of a database, it lacks the native ability to validate JWTs using RSA signatures. This project provides a set of PL/pgSQL functions that enable PostgreSQL databases to validate JWTs signed with RSA keys and also with HMAC, supporting the RSA verification algorithms RS256, RS384, RS512, and HMAC algorithms HS256, HS384, HS512.


## Features

- Validate RSA-signed and HMAC-signed JWTs within PostgreSQL.
- Support RS256, RS384, RS512, HS256, HS384, and HS512 signing algorithms.
- Validate the registered `exp`, `nbf`, `aud`, and `iss` claims.
- Centralized access control logic within the database.
- Usable with pgcrypto extension.

## Installation

To install the RSA JWT decoding functions in your PostgreSQL database, follow these steps:

1. Ensure you have the `pgcrypto` extension installed. If not, you can create it by running:

   ```sql
   CREATE EXTENSION pgcrypto;
   ```

2. Execute the SQL script `decode_jwt.sql` in your database. This will create the necessary functions for RSA JWT validation.

## Usage Example

To use the RSA JWT decoding functions, provide the JWT token and a JSON array of keys. The function `decode_jwt` returns the decoded JWT claims if the signature is valid, and null otherwise.

Here's an example of how to use the function:

```sql
SELECT jwt.decode_jwt(
    token := 'eyJraWQiOiJMYXNy...fbD5mt2VUgEIQ09LK2X5WvexGNXgwTHS2OEoADYEqlsXYW4nCKrfTnWytRqqN3QGogp2w',
    keys := jsonb_build_array(
        jwt.jwk_to_key('{"alg":"RS256","e":"AQAB","kid":"h5pxMYKBE+xzuBRuWsPl7Z6FEkJNDRQcxPkY+wJbXow=","kty":"RSA","n":"1MAoK9L...OKx5Q","use":"sig"}'::jsonb),
        jwt.jwk_to_key('{"alg":"RS256","e":"AQAB","kid":"LasrDwHasdaqE41aLs8MLZQ5BYQwKgPcs7N1GGt5Ysg=","kty":"RSA","n":"xCEddOF0-SFSM1yU...N3QGogp2w","use":"sig"}'::jsonb)
    )
);
```

Replace the `token` and keys with the appropriate JWT and key set for your application.

### Claims validation

After the signature is verified, `decode_jwt` validates the registered claims and
returns `null` (just like a signature failure) when validation fails:

- **`exp` / `nbf`** — enforced by default whenever the claim is present. A token
  with no `exp` claim is **not** rejected, so issue your tokens with an
  expiration. Pass `validate_exp := false` or `validate_nbf := false` to disable
  the corresponding check, and `leeway` to allow for clock skew.
- **`aud`** — only checked when you pass an expected `audience`. The token's
  `aud` claim may be a string or an array of strings and must contain the
  expected value.
- **`iss`** — only checked when you pass an expected `issuer`, which must equal
  the token's `iss` claim.

```sql
SELECT jwt.decode_jwt(
    token := 'eyJraWQiOiJMYXNy...',
    keys := jsonb_build_array(
        jwt.jwk_to_key('{"alg":"RS256", ...}'::jsonb)
    ),
    audience := 'postgresql',
    issuer := 'https://issuer.example.com',
    leeway := interval '30 seconds'
);
```

The full signature is:

```sql
jwt.decode_jwt(
    token text,
    keys jsonb,
    audience text default null,
    issuer text default null,
    leeway interval default '0 seconds',
    validate_exp boolean default true,
    validate_nbf boolean default true
)
```

> **Upgrading:** this version replaces the previous two-argument `decode_jwt`
> with the signature above and enforces `exp`/`nbf` by default. Existing
> `decode_jwt(token, keys)` calls keep working but will now reject expired or
> not-yet-valid tokens. Drop any objects that depend on the old function before
> re-running `decode_jwt.sql`.

## License

This project is licensed under the MIT License.
