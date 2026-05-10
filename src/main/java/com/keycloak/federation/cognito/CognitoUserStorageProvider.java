package com.keycloak.federation.cognito;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Keycloak User Storage Provider that delegates credential validation to AWS Cognito.
 *
 * Flow:
 * 1. Keycloak checks if the user exists in the local database.
 * 2. If yes, password is validated locally (this provider is not involved).
 * 3. If no, this provider looks up the user in Cognito via AdminGetUser.
 * 4. If found in Cognito, Keycloak creates a federated user reference and validates credentials.
 * 5. On successful credential validation, the user is migrated to the local database.
 * 6. Future logins for this user will be validated locally.
 */
public class CognitoUserStorageProvider implements UserStorageProvider, UserLookupProvider, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(CognitoUserStorageProvider.class);

    private final KeycloakSession session;
    private final ComponentModel model;
    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;
    private final String clientId;
    private final String clientSecret;

    public CognitoUserStorageProvider(KeycloakSession session, ComponentModel model,
                                      CognitoIdentityProviderClient cognitoClient) {
        this.session = session;
        this.model = model;
        this.cognitoClient = cognitoClient;
        this.userPoolId = model.get(CognitoUserStorageProviderFactory.CONFIG_USER_POOL_ID);
        this.clientId = model.get(CognitoUserStorageProviderFactory.CONFIG_CLIENT_ID);
        this.clientSecret = model.get(CognitoUserStorageProviderFactory.CONFIG_CLIENT_SECRET);
    }

    // ==================== UserLookupProvider ====================

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.infof("Looking up user '%s' in Cognito user pool", username);

        try {
            AdminGetUserRequest request = AdminGetUserRequest.builder()
                    .userPoolId(userPoolId)
                    .username(username)
                    .build();

            AdminGetUserResponse response = cognitoClient.adminGetUser(request);

            if (response != null && response.username() != null) {
                logger.infof("User '%s' found in Cognito, creating local Keycloak user", username);
                return createKeycloakUser(realm, response);
            }
        } catch (UserNotFoundException e) {
            logger.debugf("User '%s' not found in Cognito", username);
        } catch (CognitoIdentityProviderException e) {
            logger.warnf("Error looking up user '%s' in Cognito: [%s] %s",
                    username, e.awsErrorDetails().errorCode(), e.awsErrorDetails().errorMessage());
        } catch (Exception e) {
            logger.errorf(e, "Unexpected error looking up user '%s' in Cognito", username);
        }

        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.debugf("getUserByEmail called with '%s' - not supported for Cognito lookup", email);
        return null;
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        StorageId storageId = new StorageId(id);
        String externalId = storageId.getExternalId();
        logger.debugf("getUserById called with externalId '%s'", externalId);
        return getUserByUsername(realm, externalId);
    }

    /**
     * Creates a local Keycloak user from the Cognito user data.
     */
    private UserModel createKeycloakUser(RealmModel realm, AdminGetUserResponse cognitoUser) {
        String username = cognitoUser.username();

        UserModel localUser = session.users().addUser(realm, username);
        localUser.setEnabled(true);
        localUser.setFederationLink(model.getId());

        List<AttributeType> attributes = cognitoUser.userAttributes();
        if (attributes != null) {
            for (AttributeType attr : attributes) {
                switch (attr.name()) {
                    case "email":
                        localUser.setEmail(attr.value());
                        localUser.setEmailVerified(true);
                        break;
                    case "given_name":
                        localUser.setFirstName(attr.value());
                        break;
                    case "family_name":
                        localUser.setLastName(attr.value());
                        break;
                    default:
                        localUser.setSingleAttribute("cognito_" + attr.name(), attr.value());
                        break;
                }
            }
        }

        logger.infof("Created local Keycloak user for '%s' with federation link", username);
        return localUser;
    }

    // ==================== CredentialInputValidator ====================

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    /**
     * Validates credentials against AWS Cognito using AdminInitiateAuth.
     * If successful, stores the password locally and removes the federation link.
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        if (!(credentialInput instanceof UserCredentialModel)) {
            logger.debug("Credential input is not a UserCredentialModel, skipping.");
            return false;
        }

        if (!supportsCredentialType(credentialInput.getType())) {
            logger.debug("Unsupported credential type: " + credentialInput.getType());
            return false;
        }

        String username = user.getUsername();
        String password = credentialInput.getChallengeResponse();

        logger.infof("Attempting Cognito authentication for user: %s", username);

        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", username);
            authParams.put("PASSWORD", password);

            // If a client secret is configured, compute and include SECRET_HASH
            if (clientSecret != null && !clientSecret.trim().isEmpty()) {
                String secretHash = computeSecretHash(username);
                authParams.put("SECRET_HASH", secretHash);
                logger.debugf("SECRET_HASH computed for user '%s'", username);
            }

            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                    .userPoolId(userPoolId)
                    .clientId(clientId)
                    .authParameters(authParams)
                    .build();

            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

            if (authResponse.authenticationResult() != null) {
                logger.infof("Cognito authentication successful for user: %s. Migrating to local store.", username);
                migrateUserLocally(realm, user, password);
                return true;
            }

            if (authResponse.challengeName() != null) {
                logger.warnf("Cognito returned challenge '%s' for user: %s. Migration not supported for this state.",
                        authResponse.challengeNameAsString(), username);
                return false;
            }

            return false;

        } catch (CognitoIdentityProviderException e) {
            logger.warnf("Cognito authentication failed for user '%s': [%s] %s",
                    username, e.awsErrorDetails().errorCode(), e.awsErrorDetails().errorMessage());
            return false;
        } catch (Exception e) {
            logger.errorf(e, "Unexpected error during Cognito authentication for user: %s", username);
            return false;
        }
    }

    /**
     * Computes the SECRET_HASH required by Cognito when the App Client has a secret.
     * SECRET_HASH = Base64(HMAC_SHA256(clientSecret, username + clientId))
     */
    private String computeSecretHash(String username) {
        try {
            String message = username + clientId;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    clientSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] rawHmac = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error computing SECRET_HASH", e);
        }
    }

    /**
     * Migrates the user to Keycloak's local database with the provided password.
     * After this, future logins will be validated locally without reaching Cognito.
     */
    private void migrateUserLocally(RealmModel realm, UserModel user, String password) {
        try {
            user.credentialManager().updateCredential(
                    UserCredentialModel.password(password, false));

            user.setFederationLink(null);

            logger.infof("User '%s' migrated successfully to local store", user.getUsername());
        } catch (Exception e) {
            logger.errorf(e, "Failed to migrate user '%s' to local store", user.getUsername());
        }
    }

    @Override
    public void close() {
        // Client lifecycle is managed by the factory
    }
}
