import jwt
import boto3
import streamlit as st
import base64
import json

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
    
def decode_token(token):
    # Split the JWT into parts
    parts = token.split('.')
    header = parts[0]

    # Decode the header from base64
    decoded_header = base64.urlsafe_b64decode(header + '==').decode('utf-8')
    header_json = json.loads(decoded_header)
    return jwt.decode(token, algorithms=[header_json['alg']], options={"verify_signature": True})
