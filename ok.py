import boto3
import json
from botocore.exceptions import ClientError

def get_secret(secret_name, region_name):
    """
    Retrieve a secret from AWS Secrets Manager

    :param secret_name: Name of the secret in AWS Secrets Manager
    :param region_name: AWS region where the secret is stored
    :return: The secret value as a dictionary
    """
    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # Handle errors here
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
        else:
            raise e
    else:
        # Decrypts secret using the associated KMS key
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret)

def main():
    secret_name = "wp-creds"  # Use the provided secret name
    region_name = "us-east-1"  # Use your AWS region

    secret = get_secret(secret_name, region_name)
    print("WORDPRESS_DB_HOST:", secret.get("WORDPRESS_DB_HOST"))
    print("WORDPRESS_DB_USER:", secret.get("WORDPRESS_DB_USER"))
    print("WORDPRESS_DB_PASSWORD:", secret.get("WORDPRESS_DB_PASSWORD"))
    print("WORDPRESS_DB_NAME:", secret.get("WORDPRESS_DB_NAME"))

if __name__ == "__main__":
    main()
