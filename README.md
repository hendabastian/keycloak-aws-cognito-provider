# Keycloak 26 - AWS Cognito User Federation Provider

Seamlessly migrate users from AWS Cognito to Keycloak — without forcing password resets.

## The Problem

When migrating from AWS Cognito to Keycloak, you face a fundamental challenge: **you can't export user passwords from Cognito**. AWS doesn't provide any way to retrieve password hashes, which means a traditional bulk migration would force every user to reset their password.

For organizations with thousands of users, that's not acceptable.

## The Solution

This provider implements a **lazy migration** strategy. Instead of migrating all users at once, it migrates them one-by-one as they log in:

1. User logs into Keycloak with their existing Cognito credentials
2. Keycloak doesn't find the user locally, so it asks Cognito
3. Cognito validates the password
4. The provider creates the user in Keycloak's local database with the same password
5. Done — future logins are handled entirely by Keycloak

The user notices nothing. No password reset emails. No downtime. No migration scripts.

```
User Login
    │
    ▼
┌──────────────────┐
│ Exists in        │──── YES ──→ Validate locally (Keycloak handles it)
│ Keycloak?        │
└──────────────────┘
    │
   NO
    │
    ▼
┌──────────────────┐
│ Exists in        │──── NO ───→ Login fails
│ Cognito?         │
└──────────────────┘
    │
   YES
    │
    ▼
┌──────────────────┐
│ Password valid   │──── NO ───→ Login fails
│ in Cognito?      │
└──────────────────┘
    │
   YES
    │
    ▼
┌──────────────────┐
│ Create user in   │
│ Keycloak + store │
│ password locally │
└──────────────────┘
    │
    ▼
User is now fully in Keycloak.
Cognito is never contacted again for this user.
```

## Migration Timeline

Once deployed, your migration happens organically:

- **Day 1**: All logins go through Cognito
- **Week 1**: Active users are migrated as they log in
- **Month 1**: Most regular users are in Keycloak
- **Month 3+**: Disable the provider, decommission Cognito

You can monitor progress by checking how many users still have a federation link vs. fully local users.

## Prerequisites

- Docker and Docker Compose (for building)
- AWS Cognito User Pool with:
  - An App Client that has `ALLOW_ADMIN_USER_PASSWORD_AUTH` enabled
  - Client secret supported (the provider handles `SECRET_HASH` computation)
- AWS IAM credentials with `cognito-idp:AdminInitiateAuth` and `cognito-idp:AdminGetUser` permissions

## Building

The build runs inside a Docker container, so you don't need Java or Maven installed on your machine. Just Docker and Docker Compose.

```bash
./build.sh
```

This spins up a Maven container, compiles the project, bundles the AWS SDK into a fat JAR, and copies the result to `./output/keycloak-cognito-provider.jar`.

## Deployment

```bash
# Copy to Keycloak
cp ./output/keycloak-cognito-provider.jar /opt/keycloak/providers/

# Rebuild and restart
/opt/keycloak/bin/kc.sh build
```

Then restart Keycloak.

## Configuration

In the Keycloak Admin Console: **User Federation** → **Add provider** → **cognito-user-provider**

| Field | Description |
|-------|-------------|
| Cognito User Pool ID | e.g., `ap-southeast-1_aBcDeFgHi` |
| Cognito App Client ID | Must have `ALLOW_ADMIN_USER_PASSWORD_AUTH` enabled |
| Cognito App Client Secret | Required if the client was created with a secret |
| AWS Region | e.g., `ap-southeast-1` |
| AWS Access Key ID | Optional — leave empty to use default credential chain |
| AWS Secret Access Key | Optional — leave empty to use default credential chain |

## AWS IAM Policy

Minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:AdminInitiateAuth",
        "cognito-idp:AdminGetUser"
      ],
      "Resource": "arn:aws:cognito-idp:<region>:<account-id>:userpool/<user-pool-id>"
    }
  ]
}
```

## User Attribute Mapping

Cognito attributes are automatically mapped during migration:

| Cognito Attribute | Keycloak Property |
|-------------------|-------------------|
| `email` | Email (marked as verified) |
| `given_name` | First Name |
| `family_name` | Last Name |
| Other attributes | Stored as `cognito_<name>` |

## Credential Provider Chain

Without static credentials, the provider uses the [AWS Default Credential Provider Chain](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/credentials-chain.html):

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Java system properties
3. Web Identity Token (EKS)
4. AWS config/credentials files
5. EC2 Instance Metadata / ECS Task Role

Recommended for production on AWS infrastructure.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `user_not_found` | User doesn't exist in Cognito | Verify username exists in your Cognito User Pool |
| `Incorrect username or password` | Wrong password | User entered wrong credentials |
| `SECRET_HASH was not received` | Client has a secret but it's not configured | Add the Client Secret in provider config |
| `ADMIN_USER_PASSWORD_AUTH not enabled` | Auth flow not enabled | Enable `ALLOW_ADMIN_USER_PASSWORD_AUTH` in Cognito App Client |
| `AccessDeniedException` | IAM permissions insufficient | Add required permissions to IAM policy |

## When to Remove the Provider

Once you're confident all active users have been migrated:

1. Check for remaining users with federation links in Keycloak
2. Send password reset emails to any remaining unmigrated users
3. Disable the federation provider
4. Remove the JAR and rebuild Keycloak
5. Decommission the Cognito User Pool

## License

MIT
