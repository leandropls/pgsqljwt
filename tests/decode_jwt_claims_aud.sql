select jwt.decode_jwt(
    token := :token,
    keys := jsonb_build_array(
       jwt.jwk_to_key(:jwk)
    ),
    audience := 'postgresql'
) as decode_jwt_claims_aud;
