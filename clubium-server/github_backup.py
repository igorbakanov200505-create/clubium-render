"""Encrypted offsite *backup* of Clubium SQLite/attachments to a PRIVATE GitHub repo.

Not a database, not a durability guarantee; single-writer backup best effort.
Never use the public source repository for user data, even if encrypted.
The encryption key and fine-grained PAT must only reside in Render env secrets.
"""
from __future__ import annotations

import atexit
import base64
import binascii
import secrets
import io
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger('clubium.github_backup')
MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_RESTORED_BYTES = 40 * 1024 * 1024
DEFAULT_REMOTE_PATH = 'encrypted-backups/clubium-latest.aesgcm'
MAGIC = b'CLUBIUM_BACKUP_AES256_GCM_V1\n'
REPO_PATTERN = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')


class BackupError(RuntimeError):
    pass


class GitHubEncryptedBackup:
    def __init__(self, data_dir: Path, environ=None):
        env = os.environ if environ is None else environ
        self.data_dir = Path(data_dir)
        self.db = self.data_dir / 'smartclub.sqlite3'
        self.repo = env.get('CLUBIUM_GH_BACKUP_REPO', '').strip()
        self.token = env.get('CLUBIUM_GH_BACKUP_TOKEN', '').strip()
        self.secret = env.get('CLUBIUM_GH_BACKUP_KEY', '').strip()
        self.enabled = bool(self.repo or self.token or self.secret)
        self.first_init = env.get('CLUBIUM_GH_INIT_EMPTY', '') == '1'
        self.branch = env.get('CLUBIUM_GH_BACKUP_BRANCH', 'main').strip() or 'main'
        self.path = DEFAULT_REMOTE_PATH
        self.interval = max(30, min(3600, int(env.get('CLUBIUM_GH_BACKUP_INTERVAL', '120'))))
        self._lock = threading.RLock()
        self._cv = threading.Condition()
        self._dirty = False
        self._stop = False
        self._worker = None
        self._last_sent = 0.0
        self._remote_sha = None
        self._repo_checked = False
        self._last_error = None
        self._last_success = None
        self._last_backup_revision = None
        self._key = None
        if not self.enabled:
            return
        if not (self.repo and self.token and self.secret):
            raise BackupError('GitHub backup: configure REPO, TOKEN and KEY together in Render Environment.')
        if not REPO_PATTERN.fullmatch(self.repo):
            raise BackupError('GitHub backup: repo must have owner/private-repository format.')
        if self.repo.lower() == 'igorbakanov200505-create/clubium-render':
            raise BackupError('GitHub backup: do not use public Clubium source repository.')
        try:
            import base64 as _b64
            secret = self.secret.encode('ascii')
            key = _b64.urlsafe_b64decode(secret)
            if len(key) != 32 or _b64.urlsafe_b64encode(key) != secret:
                raise ValueError('not a canonical 256-bit key')
            self._key = AESGCM(key)
        except (ValueError, TypeError, UnicodeEncodeError, binascii.Error) as exc:
            raise BackupError('GitHub backup: key must be an AES-256 key (use generate_backup_key.py).') from exc
        if not re.fullmatch('[A-Za-z0-9._/-]{1,100}', self.branch):
            raise BackupError('GitHub backup: invalid branch name.')
        atexit.register(self.flush)

    def _request(self, method: str, endpoint: str, body=None, raw=False):
        url = 'https://api.github.com/repos/' + self.repo + endpoint
        headers = {'Authorization': 'Bearer ' + self.token,
                   'Accept': 'application/vnd.github.raw+json' if raw else 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'clubium-encrypted-backup/1.0'}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        payload = json.dumps(body, separators=(',', ':')).encode() if body is not None else None
        req = Request(url, data=payload, headers=headers, method=method)
        try:
            with urlopen(req, timeout=18) as response:
                content = response.read(MAX_ARCHIVE_BYTES * 2 + 1024)
                if response.status not in (200, 201):
                    raise BackupError('GitHub backup: unexpected HTTP response.')
                if raw:
                    return content
                return json.loads(content)
        except HTTPError as exc:
            if exc.code == 404:
                raise BackupError('GitHub backup: private repository or backup file not found (404).') from exc
            if exc.code in (401, 403):
                raise BackupError('GitHub backup: access denied or rate-limited (HTTP %s).' % exc.code) from exc
            if exc.code in (409, 422):
                raise BackupError('GitHub backup: version conflict or invalid request (HTTP %s).') from exc
            raise BackupError('GitHub backup: HTTP %s' % exc.code) from exc
        except (TimeoutError, URLError) as exc:
            raise BackupError('GitHub backup: cannot connect to GitHub API.') from exc

    def _ensure_private_repo(self):
        # Check private flag, never silently save students' data to a public repo.
        if self._repo_checked:
            return
        info = self._request('GET', '')
        if info.get('private') is not True:
            raise BackupError('GitHub backup: repository must be PRIVATE. Refusing to upload.')
        self._repo_checked = True

    def _fetch_file(self):
        endpoint = '/contents/' + quote(self.path, safe='/') + '?ref=' + quote(self.branch, safe='')
        try:
            record = self._request('GET', endpoint)
        except BackupError as exc:
            if exc.__cause__ and isinstance(exc.__cause__, HTTPError) and exc.__cause__.code == 404:
                return None, None
            raise
        if not isinstance(record, dict) or 'sha' not in record:
            raise BackupError('GitHub backup: unexpected backup file response.')
        sha = record['sha']
        if record.get('encoding') == 'base64' and record.get('content'):
            return base64.b64decode(record['content']), sha
        # GitHub returns empty JSON content for files larger than 1 MB.
        raw = self._request('GET', endpoint, raw=True)
        return raw, sha

    def initialize(self):
        """Run before importing schema or creating a new signing key."""
        if not self.enabled:
            return
        self._ensure_private_repo()
        if self.db.exists():
            # Local persistent data takes precedence. Never blindly replace it.
            # Still fetch SHA to ensure the next commit uses GitHub optimistic concurrency.
            _content, sha = self._fetch_file()
            if sha is None and not self.first_init:
                raise BackupError('No GitHub backup; set CLUBIUM_GH_INIT_EMPTY=1 for an EXPLICIT first-time seed.')
            self._remote_sha = sha
            LOG.warning('GitHub backup enabled: local database already exists; it was NOT overwritten.')
            return
        encrypted, sha = self._fetch_file()
        if encrypted is None:
            if not self.first_init:
                raise BackupError('Encrypted GitHub backup is absent. Refusing to create an empty database. '
                                  'For a truly NEW installation set CLUBIUM_GH_INIT_EMPTY=1 once.')
            LOG.warning('No encrypted GitHub backup found; explicit first-time initialization permitted.')
            return
        self._restore(encrypted)
        self._remote_sha = sha
        self._last_success = 'restored'
        LOG.warning('Restored encrypted GitHub backup before database initialization.')

    def _restore(self, encrypted):
        if len(encrypted) > MAX_ARCHIVE_BYTES:
            raise BackupError('Encrypted GitHub backup is too large for safe restore.')
        if not encrypted.startswith(MAGIC) or len(encrypted) < len(MAGIC) + 12 + 16:
            raise BackupError('Unsupported encrypted backup format.')
        nonce_start = len(MAGIC)
        nonce = encrypted[nonce_start:nonce_start + 12]
        try:
            plaintext = self._key.decrypt(nonce, encrypted[nonce_start + 12:], MAGIC)
        except InvalidTag as exc:
            raise BackupError('Cannot decrypt backup: invalid CLUBIUM_GH_BACKUP_KEY or altered file.') from exc
        try:
            with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
                members = archive.infolist()
                allowed = lambda name: name in ('smartclub.sqlite3', 'secret.key') or bool(
                    re.fullmatch(r'uploads/[0-9a-f]{32}\.(?:png|jpg|jpeg|pdf)', name))
                files = [m for m in members if not m.is_dir()]
                names = [m.filename for m in files]
                if 'smartclub.sqlite3' not in names or len(set(names)) != len(names):
                    raise BackupError('Backup is missing database or has duplicate files.')
                if any(not allowed(name) for name in names):
                    raise BackupError('Encrypted backup has unsafe file paths.')
                if sum(m.file_size for m in files) > MAX_RESTORED_BYTES:
                    raise BackupError('Encrypted backup contents too large.')
                for entry in files:
                    if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                        raise BackupError('Encrypted backup contains a symlink.')
                # Place staging files on the SAME filesystem as the final DB.
                # Render's /tmp and /app/instance may live on different mounts;
                # os.replace across mounts raises EXDEV (Invalid cross-device link).
                self.data_dir.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='.clubium-restore-', dir=self.data_dir) as tmp:
                    stage = Path(tmp)
                    for m in files:
                        dest = stage / m.filename
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with archive.open(m) as src, dest.open('wb') as dst:
                            while True:
                                chunk = src.read(64 * 1024)
                                if not chunk:
                                    break
                                dst.write(chunk)
                    c = sqlite3.connect((stage / 'smartclub.sqlite3').as_posix())
                    try:
                        if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                            raise BackupError('Restored database integrity check failed.')
                    finally:
                        c.close()
                    # Move snapshot only after archive and database have been validated.
                    self.data_dir.mkdir(parents=True, exist_ok=True)
                    for file in files:
                        target = self.data_dir / file.filename
                        target.parent.mkdir(parents=True, exist_ok=True)
                        os.replace(stage / file.filename, target)
                    for secret_file in (self.data_dir / 'secret.key',):
                        if secret_file.exists():
                            secret_file.chmod(0o600)
        except (zipfile.BadZipFile, ValueError) as exc:
            raise BackupError('Invalid or damaged encrypted archive.') from exc
        except OSError as exc:
            # A filesystem error is not evidence that the encrypted archive is corrupt.
            raise BackupError('Cannot write restored backup files to the data directory.') from exc

    def _take_snapshot(self):
        if not self.db.is_file():
            raise BackupError('Cannot back up an absent database.')
        with tempfile.TemporaryDirectory(prefix='clubium-backup-') as td:
            snap = Path(td) / 'smartclub.sqlite3'
            with sqlite3.connect(self.db) as source, sqlite3.connect(snap) as target:
                source.backup(target)
            with sqlite3.connect(snap) as c:
                if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise BackupError('Database integrity check failed; refusing backup.')
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                archive.write(snap, 'smartclub.sqlite3')
                key_path = self.data_dir / 'secret.key'
                if key_path.is_file():
                    archive.write(key_path, 'secret.key')
                attachments = self.data_dir / 'uploads'
                if attachments.exists():
                    for path in sorted(attachments.iterdir()):
                        if path.is_file() and not path.is_symlink():
                            archive.write(path, 'uploads/' + path.name)
            nonce = secrets.token_bytes(12)
            ciphertext = MAGIC + nonce + self._key.encrypt(nonce, buffer.getvalue(), MAGIC)
            if len(ciphertext) > MAX_ARCHIVE_BYTES:
                raise BackupError('Encrypted backup exceeds configured max size (15 MB).')
            return ciphertext

    def _upload(self):
        # Re-check visibility before EVERY upload, not only when the process starts.
        self._repo_checked = False
        self._ensure_private_repo()
        encrypted = self._take_snapshot()
        document = {
            'message': 'Encrypted Clubium backup (no plaintext data)',
            'branch': self.branch,
            'content': base64.b64encode(encrypted).decode('ascii'),
        }
        if self._remote_sha:
            document['sha'] = self._remote_sha
        endpoint = '/contents/' + quote(self.path, safe='/')
        response = self._request('PUT', endpoint, document)
        new_sha = response.get('content', {}).get('sha')
        if not new_sha:
            raise BackupError('GitHub reported success but no blob sha.')
        self._remote_sha = new_sha
        self._last_success = datetime.now(timezone.utc).isoformat()
        self._last_error = None
        self._last_sent = time.monotonic()
        LOG.info('Encrypted GitHub backup uploaded successfully.')

    def changed(self):
        if not self.enabled:
            return
        with self._cv:
            self._dirty = True
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name='clubium-github-backup', daemon=True)
                self._worker.start()
            self._cv.notify_all()

    def _run(self):
        while True:
            with self._cv:
                while not self._dirty and not self._stop:
                    self._cv.wait()
                if self._stop and not self._dirty:
                    return
                # Batch frequent chat posts, and stay below GitHub's write rate limits.
                wait = self.interval - (time.monotonic() - self._last_sent)
                if wait > 0 and not self._stop:
                    self._cv.wait(timeout=wait)
                    continue
                self._dirty = False
            try:
                with self._lock:
                    self._upload()
            except Exception as exc:
                self._last_error = str(exc)
                LOG.error('Encrypted backup failed: %s', str(exc))
                with self._cv:
                    self._dirty = True
                    # Retry slowly rather than hitting GitHub with repeated failing requests.
                    self._last_sent = time.monotonic() - self.interval + max(self.interval, 60)
                    self._cv.wait(timeout=60)

    def flush(self, force=False):
        if not self.enabled:
            return
        with self._lock:
            with self._cv:
                if not self._dirty and not force:
                    return
                self._dirty = False
            try:
                self._upload()
            except Exception as exc:
                self._last_error = str(exc)
                with self._cv:
                    self._dirty = True
                raise

    def status(self):
        return {'enabled': self.enabled, 'last_success': self._last_success,
                'error': self._last_error, 'pending': self._dirty,
                'interval_seconds': self.interval}
