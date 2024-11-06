import logging
import uuid
from typing import Optional

from open_webui.apps.webui.internal.db import Base, get_db
from open_webui.apps.webui.models.users import UserModel, Users
from open_webui.env import SRC_LOG_LEVELS
from pydantic import BaseModel
from sqlalchemy import Boolean, Column, String, Text
from open_webui.utils.utils import verify_password
import requests
import json
import os
from dotenv import load_dotenv

# Get the .env file
current_file_path = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_file_path, '../../../'))
env_path = os.path.join(project_root, '.env')
load_dotenv(dotenv_path=env_path)

SUPABASE_API_KEY = os.getenv('SUPABASE_API_KEY')
SUPABASE_AUTH_URL = os.getenv('SUPABASE_AUTH_URL')
SUPABASE_USERS_UPDATE_URL = os.getenv('SUPABASE_USERS_UPDATE_URL')

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

####################
# DB MODEL
####################


class Auth(Base):
    __tablename__ = "auth"

    id = Column(String, primary_key=True)
    email = Column(String)
    password = Column(Text)
    active = Column(Boolean)


class AuthModel(BaseModel):
    id: str
    email: str
    password: str
    active: bool = True


####################
# Forms
####################


class Token(BaseModel):
    token: str
    token_type: str


class ApiKey(BaseModel):
    api_key: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    profile_image_url: str


class SigninResponse(Token, UserResponse):
    pass


class SigninForm(BaseModel):
    email: str
    password: str


class ProfileImageUrlForm(BaseModel):
    profile_image_url: str


class UpdateProfileForm(BaseModel):
    profile_image_url: str
    name: str


class UpdatePasswordForm(BaseModel):
    password: str
    new_password: str


class SignupForm(BaseModel):
    name: str
    email: str
    password: str
    profile_image_url: Optional[str] = "/user.png"


class AddUserForm(SignupForm):
    role: Optional[str] = "pending"


class AuthsTable:
    def insert_new_auth(
        self,
        email: str,
        password: str,
        name: str,
        profile_image_url: str = "/user.png",
        role: str = "pending",
        oauth_sub: Optional[str] = None,
    ) -> Optional[UserModel]:
        with get_db() as db:
            log.info("insert_new_auth")

            # Generate UUID for the new user
            id = str(uuid.uuid4())

            # Create the auth model
            auth = AuthModel(
                **{"id": id, "email": email, "password": password, "active": True}
            )
            # Insert auth into the database
            result = Auth(**auth.model_dump())
            db.add(result)

            # Insert new user record
            user = Users.insert_new_user(
                id, name, email, profile_image_url, role, oauth_sub
            )
            # Commit
            db.commit()
            db.refresh(result)

            if result and user:
                # First signup is successful, now make the second signup request using requests.post
                payload = {
                    "email": email,
                    "password": password,
                    "data": {
                            "display_name": name,
                            "email": email
                        }
                }
                headers = {
                    "apikey": SUPABASE_API_KEY,
                    "Content-Type": "application/json"
                }
                
                response = requests.post(SUPABASE_AUTH_URL, headers=headers, data=json.dumps(payload))

                if response.status_code == 200:
                    log.info("Second signup successful")
                    second_signup_data = response.json()

                    if "id" in second_signup_data:
                        second_user_id = second_signup_data["id"]

                        # Update public.users table with the second ID obtained from the second signup
                        update_url = SUPABASE_USERS_UPDATE_URL.format(email)
                        update_payload = {"ai_id": second_user_id}
                        update_headers = {
                            "apikey": SUPABASE_API_KEY,
                            "Authorization": f"Bearer {SUPABASE_API_KEY}",
                            "Content-Type": "application/json",
                        }

                        update_response = requests.patch(update_url, headers=update_headers, data=json.dumps(update_payload))

                        if update_response.status_code == 204:
                            log.info(f"User {email} successfully updated with ai_id {second_user_id}")
                        else:
                            log.error(f"Failed to update user {email} with ai_id. Status: {update_response.status_code}, Response: {update_response.text}")

                else:
                    log.error(f"Second signup request failed. Status: {response.status_code}, Response: {response.text}")
                
                return user
            else:
                return None

    def authenticate_user(self, email: str, password: str) -> Optional[UserModel]:
        log.info(f"authenticate_user: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    if verify_password(password, auth.password):
                        user = Users.get_user_by_id(auth.id)
                        return user
                    else:
                        return None
                else:
                    return None
        except Exception:
            return None

    def authenticate_user_by_api_key(self, api_key: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_api_key: {api_key}")
        # if no api_key, return None
        if not api_key:
            return None

        try:
            user = Users.get_user_by_api_key(api_key)
            return user if user else None
        except Exception:
            return False

    def authenticate_user_by_trusted_header(self, email: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_trusted_header: {email}")
        try:
            with get_db() as db:
                auth = db.query(Auth).filter_by(email=email, active=True).first()
                if auth:
                    user = Users.get_user_by_id(auth.id)
                    return user
        except Exception:
            return None

    def update_user_password_by_id(self, id: str, new_password: str) -> bool:
        try:
            with get_db() as db:
                result = (
                    db.query(Auth).filter_by(id=id).update({"password": new_password})
                )
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    def update_email_by_id(self, id: str, email: str) -> bool:
        try:
            with get_db() as db:
                result = db.query(Auth).filter_by(id=id).update({"email": email})
                db.commit()
                return True if result == 1 else False
        except Exception:
            return False

    def delete_auth_by_id(self, id: str) -> bool:
        try:
            with get_db() as db:
                # Delete User
                result = Users.delete_user_by_id(id)

                if result:
                    db.query(Auth).filter_by(id=id).delete()
                    db.commit()

                    return True
                else:
                    return False
        except Exception:
            return False


Auths = AuthsTable()
