package com.keycloak.federation.cognito;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
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
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Keycloak User Storage Provider that:
 * 1. Migrates users from AWS Cognito on first login
 * 2. Sends ALL password changes (with plaintext password) to a configured webhook URL
 *
 * The federation link is kept so that updateCredential is always called by Keycloak,
 * allowing us to intercept the plaintext password and send it to the legacy system.
 * A ThreadLocal guard prevents infinite recursion when storing the password locally.
 */
public class CognitoUserStorageProvider implements UserStorageProvider, UserLookupProvider,
        CredentialInputValidator, CredentialInputUpdater {

    private static final Logger logger = Logger.getLogger(CognitoUserStorageProvider.class);

    /**
     * ThreadLocal guard to prevent infinite recursion in updateCredential.
     * When we call user.credentialManager().updateCredential() from within our own
     * updateCredential(), Keycloak routes it back to us. This flag breaks the cycle.
     */
    private static final ThreadLocal<Boolean> UPDATING_PASSWORD = ThreadLocal.withInitial(() -> Boolean.FALSE);

    private final KeycloakSession session;
    private final ComponentModel model;
    private final CognitoIdentityProviderClient cognitoClient;
    private final String userPoolId;
    private final String clientId;
    private final String clientSecret;
    private final String webhookUrl;
    private final String webhookAuthHeader;

    public CognitoUserStorageProvider(KeycloakSession session, ComponentModel model,
                                      CognitoIdentityProviderClient cognitoClient) {
        this.session = session;
        this.model = model;
        this.cognitoClient = cognitoClient;
        this.userPoolId = model.get(CognitoUserStorageProviderFactory.CONFIG_USER_POOL_ID);
        this.clientId = model.get(CognitoUserStorageProviderFactory.CONFIG_CLIENT_ID);
        this.clientSecret = model.get(CognitoUserStorageProviderFactory.CONFIG_CLIENT_SECRET);
        this.webhookUrl = model.get(CognitoUserStorageProviderFactory.CONFIG_WEBHOOK_URL);
        this.webhookAuthHeader = model.get(CognitoUserStorageProviderFactory.CONFIG_WEBHOOK_AUTH_HEADER);
    }

    // ==================== UserLookupProvider ====================

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.infof("Looking up user '%s' in Cognito user pool", username);

        UserProvider userProvider = session.getProvider(UserProvider.class);

        UserModel existingUser = userProvider.getUserByUsername(realm, username);
        if (existingUser != null) {
            logger.debugf("User '%s' already exists locally, skipping Cognito lookup", username);
            return existingUser;
        }

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
        return null;
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        StorageId storageId = new StorageId(id);
        String externalId = storageId.getExternalId();
        return getUserByUsername(realm, externalId);
    }

    private UserModel createKeycloakUser(RealmModel realm, AdminGetUserResponse cognitoUser) {
        String username = cognitoUser.username();

        UserProvider userProvider = session.getProvider(UserProvider.class);

        UserModel localUser = userProvider.getUserByUsername(realm, username);
        if (localUser != null) {
            logger.infof("User '%s' already exists locally, returning existing user", username);
            return localUser;
        }

        localUser = userProvider.addUser(realm, username);
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
        if (!supportsCredentialType(credentialType)) {
            return false;
        }
        // Only handle validation if user does NOT have a local password yet (first login from Cognito)
        UserProvider userProvider = session.getProvider(UserProvider.class);
        UserModel localUser = userProvider.getUserByUsername(realm, user.getUsername());
        if (localUser != null) {
            boolean hasLocalPassword = localUser.credentialManager()
                    .getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                    .findAny().isPresent();
            if (hasLocalPassword) {
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        if (!(credentialInput instanceof UserCredentialModel)) {
            return false;
        }
        if (!supportsCredentialType(credentialInput.getType())) {
            return false;
        }

        String username = user.getUsername();
        String password = credentialInput.getChallengeResponse();

        logger.infof("Attempting Cognito authentication for user: %s", username);

        try {
            Map<String, String> authParams = new HashMap<>();
            authParams.put("USERNAME", username);
            authParams.put("PASSWORD", password);

            if (clientSecret != null && !clientSecret.trim().isEmpty()) {
                authParams.put("SECRET_HASH", computeSecretHash(username));
            }

            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.ADMIN_USER_PASSWORD_AUTH)
                    .userPoolId(userPoolId)
                    .clientId(clientId)
                    .authParameters(authParams)
                    .build();

            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

            if (authResponse.authenticationResult() != null) {
                logger.infof("Cognito authentication successful for user: %s. Storing password locally.", username);

                // Use the ThreadLocal guard to store password without triggering our own updateCredential
                UPDATING_PASSWORD.set(Boolean.TRUE);
                try {
                    user.credentialManager().updateCredential(
                            UserCredentialModel.password(password, false));
                } finally {
                    UPDATING_PASSWORD.set(Boolean.FALSE);
                }

                // Send webhook for initial migration
                notifyWebhook(username, password, user.getEmail());
                return true;
            }

            if (authResponse.challengeName() != null) {
                logger.warnf("Cognito returned challenge '%s' for user: %s.",
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

    // ==================== CredentialInputUpdater ====================

    /**
     * Called on every password change (forgot password, admin reset, user change).
     * Uses a ThreadLocal guard to prevent infinite recursion:
     * - First call (from Keycloak): guard is false → we store password + send webhook
     * - Recursive call (from our own updateCredential): guard is true → return false immediately
     */
    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        // If we're already inside our own updateCredential call, skip to prevent recursion
        if (UPDATING_PASSWORD.get()) {
            return false;
        }

        String username = user.getUsername();
        String newPassword = input.getChallengeResponse();

        logger.infof("Password update intercepted for user '%s', sending webhook and storing locally", username);

        // Send webhook with plaintext password to legacy system
        notifyWebhook(username, newPassword, user.getEmail());

        // Store password locally using the guard to prevent re-entry
        UPDATING_PASSWORD.set(Boolean.TRUE);
        try {
            user.credentialManager().updateCredential(
                    UserCredentialModel.password(newPassword, false));
        } finally {
            UPDATING_PASSWORD.set(Boolean.FALSE);
        }

        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not supported
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }

    // ==================== Webhook ====================

    private void notifyWebhook(String username, String password, String email) {
        if (webhookUrl == null || webhookUrl.trim().isEmpty()) {
            return;
        }

        try {
            logger.infof("Sending password webhook for user '%s' to %s", username, webhookUrl);

            URL url = new URL(webhookUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);

            if (webhookAuthHeader != null && !webhookAuthHeader.trim().isEmpty()) {
                conn.setRequestProperty("Authorization", webhookAuthHeader);
            }

            String jsonPayload = String.format(
                    "{\"username\":\"%s\",\"email\":\"%s\",\"password\":\"%s\"}",
                    escapeJson(username),
                    escapeJson(email != null ? email : ""),
                    escapeJson(password)
            );

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode >= 200 && responseCode < 300) {
                logger.infof("Webhook notified successfully for user '%s' (HTTP %d)", username, responseCode);
            } else {
                logger.warnf("Webhook returned non-success status for user '%s': HTTP %d", username, responseCode);
            }

            conn.disconnect();
        } catch (Exception e) {
            logger.errorf(e, "Failed to notify webhook for user '%s'", username);
        }
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ==================== Helpers ====================

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

    @Override
    public void close() {
        // Client lifecycle is managed by the factory
    }
}
