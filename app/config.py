from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str
    celery_broker_url: str
    celery_result_backend: str
    app_secret_key: str
    debug: bool = False
    admin_email: str = "admin@example.com"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
