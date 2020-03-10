from pathlib import Path

from foxglove.settings import BaseSettings

THIS_DIR = Path(__file__).parent.resolve()


class Settings(BaseSettings):
    routes = 'main:routes'
    pg_dsn = 'postgres://postgres@localhost:5432/termsend'
    sql_path: Path = THIS_DIR / 'models.sql'

    aws_access_key: str = None
    aws_secret_key: str = None
    aws_s3_bucket: str = None
    aws_s3_region: str = None

    aws_ses_region: str = None

    class Config:
        env_file = THIS_DIR / '.env'
