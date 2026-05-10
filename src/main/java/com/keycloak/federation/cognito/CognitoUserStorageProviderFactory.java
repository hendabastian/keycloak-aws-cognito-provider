package com.keycloak.federation.cognito;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClientBuilder;

import java.util.List;

/**
 * Factory for creating CognitoUserStorageProvider instances.
 * Configurable via the Keycloak Admin Console under User Federation.
 */
public class CognitoUserStorageProviderFactory implements UserStorageProviderFactory<CognitoUserStorageProvider> {

    private static final Logger logger = Logger.getLogger(CognitoUserStorageProviderFactory.class);

    public static final String PROVIDER_ID = "cognito-user-provider";

    public static final String CONFIG_USER_POOL_ID = "cognitoUserPoolId";
    public static final String CONFIG_CLIENT_ID = "cognitoClientId";
    public static final String CONFIG_CLIENT_SECRET = "cognitoClientSecret";
    public static final String CONFIG_REGION = "cognitoRegion";
    public static final String CONFIG_ACCESS_KEY = "cognitoAccessKey";
    public static final String CONFIG_SECRET_KEY = "cognitoSecretKey";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
                .property()
                    .name(CONFIG_USER_POOL_ID)
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("Cognito User Pool ID")
                    .helpText("The AWS Cognito User Pool ID (e.g., us-east-1_aBcDeFgHi)")
                    .add()
                .property()
                    .name(CONFIG_CLIENT_ID)
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("Cognito App Client ID")
                    .helpText("The App Client ID configured in the Cognito User Pool. Must have ALLOW_ADMIN_USER_PASSWORD_AUTH enabled.")
                    .add()
                .property()
                    .name(CONFIG_CLIENT_SECRET)
                    .type(ProviderConfigProperty.PASSWORD)
                    .label("Cognito App Client Secret (optional)")
                    .helpText("The App Client Secret. Required if the App Client was created with a secret. Leave empty if no secret is configured.")
                    .secret(true)
                    .add()
                .property()
                    .name(CONFIG_REGION)
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("AWS Region")
                    .helpText("The AWS region where the Cognito User Pool is located (e.g., us-east-1)")
                    .defaultValue("us-east-1")
                    .add()
                .property()
                    .name(CONFIG_ACCESS_KEY)
                    .type(ProviderConfigProperty.STRING_TYPE)
                    .label("AWS Access Key ID (optional)")
                    .helpText("AWS Access Key ID. If left empty, the default credential provider chain will be used (recommended for EC2/ECS).")
                    .add()
                .property()
                    .name(CONFIG_SECRET_KEY)
                    .type(ProviderConfigProperty.PASSWORD)
                    .label("AWS Secret Access Key (optional)")
                    .helpText("AWS Secret Access Key. If left empty, the default credential provider chain will be used (recommended for EC2/ECS).")
                    .secret(true)
                    .add()
                .build();
    }

    @Override
    public CognitoUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        CognitoIdentityProviderClient cognitoClient = buildCognitoClient(model);
        return new CognitoUserStorageProvider(session, model, cognitoClient);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Authenticates users against AWS Cognito User Pool. " +
               "On successful authentication, migrates the user to the local Keycloak database.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
            throws ComponentValidationException {
        String userPoolId = config.get(CONFIG_USER_POOL_ID);
        String clientId = config.get(CONFIG_CLIENT_ID);
        String region = config.get(CONFIG_REGION);

        if (userPoolId == null || userPoolId.trim().isEmpty()) {
            throw new ComponentValidationException("Cognito User Pool ID is required.");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new ComponentValidationException("Cognito App Client ID is required.");
        }
        if (region == null || region.trim().isEmpty()) {
            throw new ComponentValidationException("AWS Region is required.");
        }
    }

    private CognitoIdentityProviderClient buildCognitoClient(ComponentModel model) {
        String region = model.get(CONFIG_REGION);
        String accessKey = model.get(CONFIG_ACCESS_KEY);
        String secretKey = model.get(CONFIG_SECRET_KEY);

        CognitoIdentityProviderClientBuilder builder = CognitoIdentityProviderClient.builder()
                .region(Region.of(region));

        if (accessKey != null && !accessKey.trim().isEmpty()
                && secretKey != null && !secretKey.trim().isEmpty()) {
            logger.info("Using static AWS credentials for Cognito client.");
            builder.credentialsProvider(
                    StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(accessKey, secretKey)));
        } else {
            logger.info("Using default AWS credential provider chain for Cognito client.");
            builder.credentialsProvider(DefaultCredentialsProvider.create());
        }

        return builder.build();
    }

    @Override
    public void close() {
        // Nothing to close at factory level
    }
}
