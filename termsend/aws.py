import hashlib
import hmac
import logging
from binascii import hexlify
from datetime import datetime, timezone
from functools import reduce
from typing import Any, Dict, Literal, Optional

from httpx import URL, AsyncClient

from .settings import Settings

logger = logging.getLogger('em2.smtp.aws')

_AWS_AUTH_REQUEST = 'aws4_request'
_CONTENT_TYPE = 'application/x-www-form-urlencoded'
_SIGNED_HEADERS = 'content-type', 'host', 'x-amz-date'
_CANONICAL_REQUEST = """\
{method}
{path}
{query}
{canonical_headers}
{signed_headers}
{payload_hash}"""
_AUTH_ALGORITHM = 'AWS4-HMAC-SHA256'
_CREDENTIAL_SCOPE = '{date_stamp}/{region}/{service}/{auth_request}'
_STRING_TO_SIGN = """\
{algorithm}
{x_amz_date}
{credential_scope}
{canonical_request_hash}"""
_AUTH_HEADER = (
    '{algorithm} Credential={access_key}/{credential_scope},SignedHeaders={signed_headers},Signature={signature}'
)

HOST_LOOKUP = {
    's3': 's3.amazonaws.com',
    'ses': 'email.{region}.amazonaws.com',
}


class AwsClient:
    """
    Use AWS services.
    """

    __slots__ = 'client', 'settings', 'region', 'service', 'host', 'endpoint'

    def __init__(self, client: AsyncClient, settings: Settings, service: Literal['s3', 'ses']):
        self.client = client
        self.settings = settings
        self.service = service
        if self.service == 'ses':
            self.region = settings.aws_ses_region
            self.host = f'email.{self.region}.amazonaws.com'
        else:
            self.region = settings.aws_s3_region
            bucket = self.settings.aws_s3_bucket
            if '.' in bucket:
                # assumes the bucket is a domain and is already as a CNAME record for S3
                self.host = self.settings.aws_s3_bucket
            else:
                self.host = f'{self.settings.aws_s3_bucket}.s3.amazonaws.com'

        self.endpoint = f'https://{self.host}'
        if not (self.settings.aws_access_key and self.settings.aws_secret_key):
            logger.warning('settings.aws_access_key and settings.aws_secret_key must be set to use AWS')

    async def get(
        self, path: str = '', *, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None
    ):
        return await self.request('GET', path, None, params, headers)

    async def post(
        self,
        path: str = '',
        *,
        data: Optional[bytes] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        return await self.request('POST', path, data, params, headers)

    async def request(
        self,
        method: Literal['GET', 'POST'],
        path: str,
        data: Optional[bytes],
        params: Optional[Dict[str, Any]],
        headers: Optional[Dict[str, str]],
    ):
        url = URL(f'https://{self.host}{path}', params=[(k, v) for k, v in sorted((params or {}).items())])
        r = await self.client.request(
            method, url, data=data, headers=self._auth_headers(method, url, headers or {}, data)
        )
        if r.status_code != 200:
            debug(r.status_code, r.content, r.url)
        r.raise_for_status()
        return r

    def _auth_headers(
        self, method: Literal['GET', 'POST'], url: URL, headers: Dict[str, str], data: Optional[bytes] = None
    ):
        n = utcnow()
        x_amz_date = n.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = n.strftime('%Y%m%d')
        data = data or b''
        std_headers = {'content-type': _CONTENT_TYPE, 'host': self.host, 'x-amz-date': x_amz_date}
        all_headers = {k.lower(): v for k, v in sorted({**std_headers, **headers}.items())}
        ctx = dict(
            method=method,
            path=url.path,
            query=url.query,
            access_key=self.settings.aws_access_key,
            algorithm=_AUTH_ALGORITHM,
            x_amz_date=x_amz_date,
            auth_request=_AWS_AUTH_REQUEST,
            content_type=_CONTENT_TYPE,
            date_stamp=date_stamp,
            host=self.host,
            payload_hash=hashlib.sha256(data).hexdigest(),
            region=self.region,
            service=self.service,
            signed_headers=';'.join(all_headers.keys()),
        )
        ctx.update(credential_scope=_CREDENTIAL_SCOPE.format(**ctx))
        canonical_headers = ''.join(f'{k}:{v}\n' for k, v in all_headers.items())

        canonical_request = _CANONICAL_REQUEST.format(canonical_headers=canonical_headers, **ctx).encode()

        s2s = _STRING_TO_SIGN.format(canonical_request_hash=hashlib.sha256(canonical_request).hexdigest(), **ctx)

        key_parts = (
            b'AWS4' + self.settings.aws_secret_key.encode(),
            date_stamp,
            self.region,
            self.service,
            _AWS_AUTH_REQUEST,
            s2s,
        )
        signature = reduce(lambda key, msg: hmac.new(key, msg.encode(), hashlib.sha256).digest(), key_parts)

        authorization_header = _AUTH_HEADER.format(signature=hexlify(signature).decode(), **ctx)
        all_headers.update(
            {'Authorization': authorization_header, 'X-Amz-Content-sha256': hashlib.sha256(data).hexdigest(),}
        )
        return all_headers


EPOCH = datetime(1970, 1, 1)
EPOCH_TZ = EPOCH.replace(tzinfo=timezone.utc)


def to_unix_s(dt: datetime) -> int:
    if dt.utcoffset() is None:
        diff = dt - EPOCH
    else:
        diff = dt - EPOCH_TZ
    return int(round(diff.total_seconds()))


def utcnow():
    return datetime.utcnow().replace(tzinfo=timezone.utc)
