"""Elasticsearch client for shipping logs to data streams."""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

logger = logging.getLogger(__name__)


class ESClient:
    """Elasticsearch client with bulk indexing support for data streams."""

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
        index: Optional[str] = None,
        dataset: str = "syslog",
        namespace: str = "default",
        buffer_size: int = 500,
        verify_certs: bool = True
    ):
        """Initialize Elasticsearch client for data streams."""
        self.dataset = dataset.lower()
        self.namespace = namespace.lower()

        if index:
            self.index = index.lower()
            self._parse_index_name(self.index)
        else:
            self.index = f"logs-{self.dataset}-{self.namespace}"

        self.buffer_size = buffer_size
        self._buffer: List[Dict] = []
        self._total_indexed = 0
        self._total_failed = 0

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
        logger.info(f"Data stream: {self.index}")
        logger.info(f"  dataset: {self.dataset}, namespace: {self.namespace}")

    def _parse_index_name(self, index: str) -> None:
        """Parse dataset and namespace from index name if possible."""
        parts = index.split('-')
        if len(parts) >= 3 and parts[0] == 'logs':
            self.dataset = parts[1]
            self.namespace = '-'.join(parts[2:])

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
        facility = facility if facility is not None else 1  # user
        severity = severity if severity is not None else 6  # informational
        hostname = hostname or "unknown"
        app_name = app_name or "unknown"
        pid = pid if pid is not None else 0
        message = message or ""
        raw_message = raw_message or message

        ts = timestamp or datetime.now(timezone.utc)

        # Proper timestamp format with milliseconds
        if ts.tzinfo is None:
            ts_str = ts.strftime('%Y-%m-%dT%H:%M:%S.') + f'{ts.microsecond // 1000:03d}Z'
        else:
            ts_utc = ts.astimezone(timezone.utc)
            ts_str = ts_utc.strftime('%Y-%m-%dT%H:%M:%S.') + f'{ts_utc.microsecond // 1000:03d}Z'

        # Build ECS-compliant document
        doc = {
            "_op_type": "create",
            "_index": self.index,
            "_source": {
                "@timestamp": ts_str,

                "data_stream": {
                    "type": "logs",
                    "dataset": self.dataset,
                    "namespace": self.namespace
                },

                "message": str(message),

                "host": {
                    "name": str(hostname)
                },

                "process": {
                    "name": str(app_name),
                    "pid": int(pid)
                },

                "log": {
                    "level": self.SEVERITY_NAMES.get(severity, "info"),
                    "syslog": {
                        "facility": {
                            "code": int(facility),
                            "name": self.FACILITY_NAMES.get(facility, "user")
                        },
                        "severity": {
                            "code": int(severity),
                            "name": self.SEVERITY_NAMES.get(severity, "info")
                        },
                        "priority": int(facility * 8 + severity)
                    }
                },

                "event": {
                    "original": str(raw_message),
                    "kind": "event"
                },

                "ecs": {
                    "version": "8.11.0"
                }
            }
        }

        # Map severity to event.type
        if severity <= 3:
            doc["_source"]["event"]["type"] = ["error"]
        else:
            doc["_source"]["event"]["type"] = ["info"]

        if category:
            doc["_source"]["event"]["category"] = [category]

        if metadata:
            doc["_source"]["labels"] = metadata

        if extra_fields:
            doc["_source"]["custom"] = extra_fields

        self._buffer.append(doc)

        if len(self._buffer) >= self.buffer_size:
            self.flush()

    def flush(self) -> Tuple[int, int]:
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

            logger.debug(f"Indexed {success}/{buffer_len} to '{self.index}'")
            if errors > 0:
                logger.warning(f"Failed: {errors}")
                if isinstance(failed, list):
                    for i, err in enumerate(failed[:3]):
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
        """Get client statistics."""
        return {
            "total_indexed": self._total_indexed,
            "total_failed": self._total_failed,
            "buffer_size": len(self._buffer),
            "index": self.index,
            "dataset": self.dataset,
            "namespace": self.namespace
        }

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
