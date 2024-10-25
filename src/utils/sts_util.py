import jwt
import boto3
import streamlit as st
import base64
import json
import requests

def assume_role_with_token(iam_token):
    """
    Assume IAM role using the IAM OIDC idToken.
    """
    decoded_token = decode_token(iam_token)
    sts_client = boto3.client("sts", region_name=st.session_state.REGION)
    response = sts_client.assume_role(
        RoleArn=st.session_state.IAM_ROLE,
        RoleSessionName="qapp",
        ProvidedContexts=[
            {
                "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
                "ContextAssertion": decoded_token["sts:identity_context"],
            }
        ],
    )
    st.session_state.aws_credentials = response["Credentials"]
    



def get_public_key(kid):
    # Cognito JWKs URL
    jwks_url = f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_IQZP3cEKL/.well-known/jwks.json"

    # Fetch the JWKs
    response = requests.get(jwks_url)
    jwks = response.json()

    for key in jwks['keys']:
        if key['kid'] == kid:
            return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    raise ValueError("Public key not found")

def get_alg(token):
    # Split the JWT into parts
    parts = token.split('.')
    header = parts[0]
    # Decode the header from base64
    decoded_header = base64.urlsafe_b64decode(header + '==').decode('utf-8')
    header_json = json.loads(decoded_header)
    return header_json['alg']

def decode_token(token):
    
    # Cognito JWKs URL
    jwks_url = f"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_IQZP3cEKL/.well-known/jwks.json"

    # Fetch the JWKs
    response = requests.get(jwks_url)
    jwks = response.json()
    
    header = jwt.get_unverified_header(token)
    # raise Exception(header["alg"])

    for index, public_key in enumerate(jwks['keys']):
        try:
            return jwt.decode(token, public_key, algorithms=[get_alg(token)], options={"verify_signature": True})
        except Exception as e:
            if index == len(jwks['keys']) - 1:
                raise e
            else:
                continue
                
    # # Decode header to get `kid`
    # header = jwt.get_unverified_header(token)
    # kid = header["kid"]
    # # Load your known public key (in PEM format)
    # with open("public_key.pem", "r") as key_file:
    #     public_key = key_file.read()
        

    # # Retrieve the appropriate public key
    # public_key = get_public_key(kid)

    # return jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_signature": True})

