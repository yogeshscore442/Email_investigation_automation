from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import Config

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[Config.RATELIMIT_DEFAULT] if Config.ENABLE_RATE_LIMITING else [],
    storage_uri="memory://"
)

