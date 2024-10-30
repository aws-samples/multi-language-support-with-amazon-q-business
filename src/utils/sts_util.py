import jwt
import boto3
import streamlit as st
import base64
import json
import requests
import logging

# Configure logging to log to a file
logging.basicConfig(filename='log.txt', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def assume_role_with_token(iam_token):
    """
    Assume IAM role using the IAM OIDC idToken.
    """
    decoded_token = decode_token(iam_token)
    
    if not decoded_token:
        logger.error("Failed to decode JWT token.")
        raise ValueError("The provided JWT token could not be decoded.")
    
    sts_client = boto3.client("sts", region_name=st.session_state.REGION)
    response = sts_client.assume_role(
        RoleArn=st.session_state.IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token.get("sts:identity_context"),
            }
        ],
    )
    st.session_state.aws_credentials = response["Credentials"]

def decode_token(token):
    # Cognito JWKs URL
    jwks_url = f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_IQZP3cEKL/.well-known/jwks.json"

    # Fetch the JWKs
    response = requests.get(jwks_url)
    jwks = response.json()
    
    # Log the entire JWKS response
    logger.debug(f"JWKS fetched: {json.dumps(jwks, indent=2)}")
    
    # Iterate over all keys since there's no kid
    for index, jwk in enumerate(jwks['keys']):
        # Check if the key type is EC (Elliptic Curve)
        if jwk.get("kty") != "EC":
            continue

        try:
            # Convert the JWK to a PEM-formatted key for ECDSA
            public_key = jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(jwk))
            # Log the public key
            logger.debug(f"Attempting to decode with public key: {public_key}")
            # Attempt to decode the token using ES384
            return jwt.decode(token, public_key, algorithms=["ES384"], options={"verify_signature": True})
        except jwt.InvalidTokenError as e:
            logger.debug(f"Failed to decode with key {index}: {e}")
            continue

    # If no valid key was found
    logger.error("Unable to decode JWT with any of the provided public keys.")
    return None

def get_alg(token):
    # Split the JWT into parts
    parts = token.split('.')
    header = parts[0]
    # Decode the header from base64
    decoded_header = base64.urlsafe_b64decode(header + '==').decode('utf-8')
    header_json = json.loads(decoded_header)
    return header_json['alg']