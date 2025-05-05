import json
from http.client import HTTPException

from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakAuthenticationError, KeycloakPostError, KeycloakGetError
from django.conf import settings


class KeycloakService:
    """
        A service class to handle interactions with Keycloak for authentication and user management.
    """

    def __init__(self):
        """
            Initializes the KeycloakService with configurations for Keycloak OpenID and admin access.
        """
        self.keycloak_openid = KeycloakOpenID(
            server_url=settings.KEYCLOAK_SERVER_URL,
            client_id=settings.KEYCLOAK_SUPER_ADMIN_CLIENT_NAME,
            realm_name=settings.KEYCLOAK_SUPER_ADMIN_REALM
        )

        self.keycloak_openid_normal_user = KeycloakOpenID(
            server_url=settings.KEYCLOAK_SERVER_URL,
            client_id=settings.KEYCLOAK_CLIENT_ID,
            realm_name=settings.KEYCLOAK_REALM,
            client_secret_key=settings.KEYCLOAK_CLIENT_SECRET
        )

    @staticmethod
    def get_user_id_from_token(token):
        try:
            token_info = KeycloakService().keycloak_openid.decode_token(token, options={"verify_signature": True})
            return token_info.get("sub")
        except Exception:
            return None

    @staticmethod
    def get_keycloak_user(user_id):
        try:
            return KeycloakService().keycloak_openid.userinfo(user_id)
        except Exception:
            return None

    @staticmethod
    def get_admin_token():
        """
        Obtain an admin token using superuser credentials.

        Returns:
            dict: The token data obtained from Keycloak.

        Raises:
            HTTPException: If obtaining the token fails, raises an HTTP 400 or 401 error with a relevant error description.
        """
        try:
            token = KeycloakService().keycloak_openid.token(
                username=settings.KEYCLOAK_SUPER_USER_USERNAME,
                password=settings.KEYCLOAK_SUPER_USER_PASSWORD,
                grant_type='password',
                client_id=settings.KEYCLOAK_SUPER_ADMIN_CLIENT_NAME,
            )
            return token
        except KeycloakPostError as e:
            raise HTTPException(status_code=400, detail=json.loads(e.response_body.decode('utf-8')).get('error'))
        except KeycloakAuthenticationError as e:
            raise HTTPException(status_code=401, detail=json.loads(e.response_body.decode('utf-8')).get('error'))

    @staticmethod
    def get_keycloak_add_user_realm():
        """
        Obtain a KeycloakAdmin instance authenticated with the admin token.

        Returns:
            KeycloakAdmin: The KeycloakAdmin instance.

        Raises:
            HTTPException: If obtaining the admin instance fails, raises an HTTP 404 error with a relevant error description.
        """
        token = KeycloakService().get_admin_token()
        try:
            return KeycloakAdmin(
                server_url=settings.KEYCLOAK_SERVER_URL,
                realm_name=settings.KEYCLOAK_REALM,
                token=token,
                verify=True,
            )
        except KeycloakGetError as e:
            raise HTTPException(status_code=404, detail=json.loads(e.response_body.decode('utf-8')).get('error'))

    @staticmethod
    def create_keycloak_user(username, email, first_name, last_name, password):
        keycloak_admin = KeycloakService().get_keycloak_add_user_realm()
        try:
            user_id = keycloak_admin.create_user({
                "username": username,
                "email": email,
                "emailVerified": True,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": True,
                "credentials": [{"value": password, "type": "password"}]
            })
            return {"status": "success", "user_id": user_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @staticmethod
    def update_keycloak_user(user_id, **kwargs):
        keycloak_admin = KeycloakService().get_keycloak_add_user_realm()
        try:
            keycloak_admin.update_user(user_id=user_id, payload=kwargs)
            return {"status": "success"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


