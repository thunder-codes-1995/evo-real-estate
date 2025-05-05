from pydantic_settings import BaseSettings

import environ
env = environ.Env(
    BUSINESS_CODE=(str, "ee")
)
environ.Env.read_env("./.env")


mongodb_url = env('MONGODB_URL')
mongodb_database = env('MONGODB_DATABASE')
business_code = env('BUSINESS_CODE')

uvicorn_host = env('UVICORN_HOST')
uvicorn_port = env('UVICORN_PORT')
debug_mode = env('DEBUG_MODE')

class CommonSettings(BaseSettings):
    APP_NAME: str = "Evo-Prop FAST API"
    DEBUG_MODE: bool = bool(debug_mode)
    BUSINESS_CODE: str = business_code
    MONGODB_URL: str = mongodb_url


class ServerSettings(BaseSettings):
    HOST: str = uvicorn_host
    PORT: int = uvicorn_port


class DatabaseSettings(BaseSettings):
    DB_URL: str = mongodb_url
    DB_NAME: str = mongodb_database
    BUSINESS_DB: str = business_code


class Settings(CommonSettings, ServerSettings, DatabaseSettings):
    pass


settings = Settings()
