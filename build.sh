#!/usr/bin/env bash
set -e

echo "=== Building Keycloak Cognito Provider ==="
echo "Using Docker Compose to build the JAR (no local dependencies required)..."
echo ""

docker compose run --rm builder

echo ""
echo "=== Build Complete ==="
echo "JAR file available at: ./output/keycloak-cognito-provider.jar"
echo ""
echo "To deploy, copy the JAR to your Keycloak providers directory:"
echo "  cp ./output/keycloak-cognito-provider.jar /opt/keycloak/providers/"
echo ""
echo "Then restart Keycloak or run: /opt/keycloak/bin/kc.sh build"
