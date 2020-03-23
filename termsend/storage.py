import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta
from math import ceil
from typing import Any, AsyncIterable, Dict, List, Optional
from urllib.parse import urlencode
from xml.etree import ElementTree

from httpx import AsyncClient
from pydantic import BaseModel, validator

from .aws import AwsClient, to_unix_s, utcnow
from .settings import Settings

# rounding of download link expiry time, this allows the CDN to efficiently cache download links
expiry_rounding = 100
# removing xmlns="http://s3.amazonaws.com/doc/2006-03-01/" from xml makes it much easier to parse
xmlns = 'http://s3.amazonaws.com/doc/2006-03-01/'
xmlns_re = re.compile(f' xmlns="{re.escape(xmlns)}"'.encode())


class File(BaseModel):
    key: str
    last_modified: datetime
    size: int
    e_tag: str
    storage_class: str

    @validator('e_tag')
    def set_ts_now(cls, v):
        return v.strip('"')

    class Config:
        @classmethod
        def alias_generator(cls, string: str) -> str:
            # this is the same as `alias_generator = to_camel` above
            return ''.join(word.capitalize() for word in string.split('_'))


class S3:
    __slots__ = '_settings', '_client'

    def __init__(self, client: AsyncClient, settings: Settings):
        self._client = AwsClient(client, settings, 's3')
        self._settings = settings

    async def list(
        self, prefix: Optional[str] = None, *, continuation_token: Optional[str] = None
    ) -> AsyncIterable[File]:
        """
        List S3 files with the given prefix
        """
        assert prefix is None or not prefix.startswith('/'), 'the prefix to filter by should not start with a "/"'
        while True:
            params = {'list-type': 2, 'prefix': prefix, 'continuation-token': continuation_token}
            r = await self._client.get(params={k: v for k, v in params.items() if v is not None})

            xml_root = ElementTree.fromstring(xmlns_re.sub(b'', r.content))
            for c in xml_root.findall('Contents'):
                yield File.parse_obj({v.tag: v.text for v in c})
            if xml_root.find('IsTruncated').text == 'false':
                break

            continuation_token = xml_root.find('NextContinuationToken').text

    async def delete_multiple(self, *keys: str):
        xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<Delete xmlns="{xmlns}">'
            f' {"".join(f"<Object><Key>{k}</Key></Object>" for k in keys)}'
            f' <Quiet>true</Quiet>'
            f'</Delete>'
        )
        check = base64.b64encode(hashlib.md5(xml.encode()).digest()).decode()
        r = await self._client.post('', data=xml.encode(), params=dict(delete=1), headers={'Content-MD5': check})
        debug(r.content)

    def signed_download_url(self, path: str, version: Optional[str] = None, max_age: int = 30) -> str:
        """
        Sign a path to authenticate download.

        The url is valid for between max_age seconds and max_age + expiry_rounding seconds.

        https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth
        """
        assert not path.startswith('/'), 'path should not start with /'
        min_expires = to_unix_s(utcnow()) + max_age
        expires = int(ceil(min_expires / expiry_rounding) * expiry_rounding)
        to_sign = f'GET\n\n\n{expires}\n/{self._settings.aws_s3_bucket}/{path}'
        signature = self._signature(to_sign.encode())
        args = {'AWSAccessKeyId': self._settings.aws_access_key, 'Signature': signature, 'Expires': expires}
        if version:
            args['v'] = version
        return f'https://{self._settings.aws_s3_bucket}/{path}?{urlencode(args)}'

    def signed_upload_url(
        self, *, path: str, filename: str, content_type: str, size: int, content_disp: bool = True,
    ) -> Dict[str, Any]:
        """
        https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-post-example.html
        """
        assert path.endswith('/'), 'path must end with "/"'
        assert not path.startswith('/'), 'path must not start with "/"'
        key = path + filename
        policy = {
            'expiration': f'{utcnow() + timedelta(seconds=60):%Y-%m-%dT%H:%M:%SZ}',
            'conditions': [
                {'bucket': self._settings.aws_s3_bucket},
                {'key': key},
                {'content-type': content_type},
                ['content-length-range', size, size],
            ],
        }

        fields = {'Key': key, 'Content-Type': content_type, 'AWSAccessKeyId': self._settings.aws_access_key}
        if content_disp:
            disp = {'Content-Disposition': f'attachment; filename="{filename}"'}
            policy['conditions'].append(disp)
            fields.update(disp)

        b64_policy: bytes = base64.b64encode(json.dumps(policy).encode())
        fields.update(Policy=b64_policy.decode(), Signature=self._signature(b64_policy))
        return dict(url=f'https://{self._settings.aws_s3_bucket}/', fields=fields)

    def _signature(self, to_sign: bytes) -> str:
        s = hmac.new(self._settings.aws_secret_key.encode(), to_sign, hashlib.sha1).digest()
        return base64.b64encode(s).decode()
