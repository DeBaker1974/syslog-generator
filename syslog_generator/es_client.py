"""Elasticsearch client for shipping logs."""

import logging
from datetime import datetime
from typing import Optional, Dict, Any

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logger = logging.getLogger(__name__)


class ESClient:
    """Elasticsearch client with bulk indexing support."""

    FACILITY_NAMES = {
        0: "kern", 1: "user", 2: "mail", 3: "daemon",
        4: "auth", 5: "syslog", 6: "lpr", 7: "news",
        8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
        16: "local0", 17: "local1", 18: "local2", 19: "local3",
        20: "local4", 21: "local5", 22: "local6", 23: "local7"
    }

    SEVERITY_NAMES = {
        0: "emergency", 1: "alert", 2: "critical", 3: "error",
        4: "warning", 5: "notice", 6: "informational", 7: "debug"
    }

    def __init__(
        self,
        url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index: str = "logs",
        buffer_size: int = 500,
        verify_certs: bool = True
    ):
        """Initialize Elasticsearch client."""
        self.index = index  # Just "logs" - no suffix
        self.buffer_size = buffer_size
        self._buffer = []
        self._total_indexed = 0
        self._total_failed = 0

        # Build connection kwargs
        es_kwargs = {
            "hosts": [url],
            "verify_certs": verify_certs,
        }

        if url.startswith("https://") and not verify_certs:
            import urllib3
            urllib3.disable_warnings()
            es_kwargs["ssl_show_warn"] = False

        if api_key:
            es_kwargs["api_key"] = api_key
            auth_method = "API Key"
        elif username and password:
            es_kwargs["basic_auth"] = (username, password)
            auth_method = f"Basic Auth ({username})"
        else:
            raise ValueError("Either api_key or username/password must be provided")

        logger.debug(f"Connecting to {url} using {auth_method}")
        self.client = Elasticsearch(**es_kwargs)

        if not self.client.ping():
            raise ConnectionError(f"Cannot connect to Elasticsearch at {url}")

        info = self.client.info()
        logger.info(f"Connected to ES: {info['cluster_name']} (v{info['version']['number']})")
        logger.info(f"Target index: {self.index}")

    def index_log(
        self,
        message: str,
        facility: int,
        severity: int,
        hostname: str,
        app_name: str,
        pid: int,
        raw_message: str,
        timestamp: Optional[datetime] = None,
        category: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **extra_fields
    ) -> None:
        """Add a log document to the buffer."""
        ts = timestamp or datetime.utcnow()

        # Ensure proper ISO format with Z suffix
        ts_str = ts.isoformat()
        if not ts_str.endswith('Z'):
            ts_str += 'Z'

        doc = {
            "_op_type": "create",
            "_index": self.index,  # Just "logs"
            "_source": {
                "@timestamp": ts_str,
                "message": message,
                "syslog": {
                    "facility": {
                        "code": facility,
                        "name": self.FACILITY_NAMES.get(facility, "unknown")
                    },
                    "severity": {
                        "code": severity,
                        "name": self.SEVERITY_NAMES.get(severity, "unknown")
                    },
                    "priority": facility * 8 + severity
                },
                "host": {
                    "name": hostname
                },
                "process": {
                    "name": app_name,
                    "pid": pid
                },
                "event": {
                    "original": raw_message,
                    "dataset": "syslog"
                },
                "log": {
                    "level": self.SEVERITY_NAMES.get(severity, "unknown").upper()
                }
            }
        }

        if category:
            doc["_source"]["event"]["category"] = category

        if metadata:
            doc["_source"]["metadata"] = metadata

        if extra_fields:
            doc["_source"]["custom"] = extra_fields

        self._buffer.append(doc)

        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> tuple[int, int]:
        """Flush buffered documents to Elasticsearch."""
        if not self._buffer:
            return 0, 0

        buffer_len = len(self._buffer)
        success = 0
        errors = 0

        try:
            success, failed = bulk(
                self.client,
                self._buffer,
                raise_on_error=False,
                raise_on_exception=False
            )
            errors = len(failed) if isinstance(failed, list) else 0
            self._total_indexed += success
            self._total_failed += errors
            if success > 0:
                self.client.indices.refresh(index=self.index)

            logger.debug(f"Indexed {success}/{buffer_len} to '{self.index}'")
            if errors > 0:
                logger.warning(f"Failed: {errors}")
                # Log first few error details
                if isinstance(failed, list):
                    for i, err in enumerate(failed[:3]):  # Show first 3 errors
                        logger.error(f"  Error {i+1}: {err}")

        except Exception as e:
            logger.error(f"Bulk error: {e}")
            self._total_failed += buffer_len
        finally:
            self._buffer = []

        return success, errors


    def close(self) -> None:
        """Flush remaining documents and close."""
        if self._buffer:
            logger.info(f"Flushing {len(self._buffer)} remaining docs...")
        self.flush()
        self.client.close()
        logger.info(f"Total indexed: {self._total_indexed}, failed: {self._total_failed}")

    @property
    def stats(self) -> dict:
        return {
            "total_indexed": self._total_indexed,
            "total_failed": self._total_failed,
            "buffer_size": len(self._buffer),
            "index": self.index
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
