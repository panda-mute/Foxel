import asyncio
import mimetypes
import posixpath
import stat as statmod

import smbclient
from smbclient import shutil as smb_shutil
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from ._remote import clean_path, entry, paginate


class SMBAdapter:
    """SMB2/3 share adapter backed by smbprotocol."""

    def __init__(self, record):
        self.record = record
        cfg = record.config or {}
        self.server = str(cfg.get("server") or cfg.get("address") or "").strip()
        self.share = str(cfg.get("share") or cfg.get("share_name") or "").strip("/")
        self.guest = bool(cfg.get("guest", False))
        if self.guest:
            self.username = cfg.get("username") or "guest"
            self.password = cfg.get("password") or "guest"
        else:
            self.username = cfg.get("username") or ""
            self.password = cfg.get("password") or ""
        self.root = clean_path(cfg.get("root") or "")
        self.timeout = float(cfg.get("timeout", 30))
        self.port = int(cfg.get("port", 445))
        if not self.server or not self.share:
            raise ValueError("SMB requires server and share")
        if any(c in self.server for c in "/\\") or any(c in self.share for c in "/\\"):
            raise ValueError("SMB server and share must be single path components")
        self.base = "\\\\" + self.server.strip("\\/") + "\\" + self.share.replace("/", "\\")
        self._options = {"username": self.username, "password": self.password, "port": self.port,
                         "connection_timeout": self.timeout, "connection_cache": {}}
        self._operation_lock = asyncio.Lock()
        if self.guest:
            # Guest sessions are negotiated after failed credentials and cannot sign or encrypt.
            self._options.update(auth_protocol="ntlm", encrypt=False, require_signing=False)

    def get_effective_root(self, sub_path):
        return "/".join(filter(None, (self.root, clean_path(sub_path))))

    def _path(self, root, rel=""):
        combined = clean_path("/".join(filter(None, (root or self.root, rel))))
        return self.base if not combined else self.base + "\\" + combined.replace("/", "\\")

    async def _call(self, func, *args, **kwargs):
        return await asyncio.to_thread(func, *args, **kwargs)

    async def _smb_call(self, func, *args, with_options=True, **kwargs):
        async with self._operation_lock:
            if with_options:
                kwargs = {**kwargs, **self._options}
            return await asyncio.to_thread(func, *args, **kwargs)

    async def list_dir(self, root, rel, page_num=1, page_size=50, sort_by="name", sort_order="asc"):
        path = self._path(root, rel)
        def scan():
            result = []
            with smbclient.scandir(path, **self._options) as iterator:
                for item in iterator:
                    info = item.stat(follow_symlinks=False)
                    is_dir = statmod.S_ISDIR(info.st_mode)
                    result.append(entry(item.name, is_dir, info.st_size, info.st_mtime, path=item.path))
            return result
        items = await self._smb_call(scan, with_options=False)
        return paginate(items, page_num, page_size, sort_by, sort_order)

    async def stat_file(self, root, rel):
        path = self._path(root, rel)
        try:
            info = await self._smb_call(smbclient.stat, path, follow_symlinks=False)
        except FileNotFoundError:
            raise FileNotFoundError(rel)
        return entry(posixpath.basename(clean_path(rel)), statmod.S_ISDIR(info.st_mode), info.st_size, info.st_mtime,
                     path=path)

    async def exists(self, root, rel):
        try:
            await self.stat_file(root, rel)
            return True
        except FileNotFoundError:
            return False

    async def stat_path(self, root, rel):
        try:
            item = await self.stat_file(root, rel)
            return {**item, "exists": True, "path": rel}
        except FileNotFoundError:
            return {"exists": False, "is_dir": None, "path": rel}

    async def read_file(self, root, rel):
        path = self._path(root, rel)
        def read():
            with smbclient.open_file(path, mode="rb", **self._options) as file:
                return file.read()
        return await self._smb_call(read, with_options=False)

    async def stream_file(self, root, rel, range_header):
        item = await self.stat_file(root, rel)
        if item["is_dir"]:
            raise IsADirectoryError(rel)
        start, end = 0, item["size"] - 1
        if range_header:
            try:
                if not range_header.startswith("bytes=") or "," in range_header:
                    raise ValueError
                begin, finish = range_header[6:].split("-")
                if begin:
                    start = int(begin)
                    end = int(finish) if finish else item["size"] - 1
                else:
                    suffix = int(finish)
                    if suffix <= 0:
                        raise ValueError
                    start, end = max(0, item["size"] - suffix), item["size"] - 1
                if start < 0 or start >= item["size"] or end < start:
                    raise ValueError
                end = min(end, item["size"] - 1)
            except ValueError:
                raise HTTPException(416, "Requested Range Not Satisfiable",
                                    headers={"Content-Range": f"bytes */{item['size']}"})
        path = self._path(root, rel)
        length = max(0, end - start + 1)

        async def body():
            file = await self._smb_call(smbclient.open_file, path, mode="rb")
            remaining = length
            try:
                await self._smb_call(file.seek, start, with_options=False)
                while remaining:
                    chunk = await self._smb_call(file.read, min(1024 * 1024, remaining), with_options=False)
                    if not chunk:
                        raise IOError("SMB file was truncated during download")
                    remaining -= len(chunk)
                    yield chunk
            finally:
                await self._smb_call(file.close, with_options=False)

        headers = {"Content-Length": str(length), "Accept-Ranges": "bytes"}
        if range_header:
            headers["Content-Range"] = f"bytes {start}-{end}/{item['size']}"
        return StreamingResponse(body(), status_code=206 if range_header else 200, headers=headers,
                                 media_type=mimetypes.guess_type(rel)[0] or "application/octet-stream")

    async def write_file(self, root, rel, data):
        async def chunks():
            yield data
        return await self.write_file_stream(root, rel, chunks())

    async def write_file_stream(self, root, rel, data_iter):
        if not clean_path(rel):
            raise ValueError("Cannot overwrite mount root")
        path = self._path(root, rel)
        await self._smb_call(smbclient.makedirs, path.rsplit("\\", 1)[0], exist_ok=True)
        file = await self._smb_call(smbclient.open_file, path, mode="wb")
        size = 0
        try:
            async for chunk in data_iter:
                if chunk:
                    written = await self._smb_call(file.write, chunk, with_options=False)
                    if written != len(chunk):
                        raise IOError("Incomplete SMB write")
                    size += written
        finally:
            await self._smb_call(file.close, with_options=False)
        return size

    async def write_upload_file(self, root, rel, file_obj, filename=None, file_size=None, content_type=None):
        file_obj.seek(0)
        async def chunks():
            while chunk := await self._call(file_obj.read, 1024 * 1024):
                yield chunk
        return {"size": await self.write_file_stream(root, rel, chunks())}

    async def mkdir(self, root, rel):
        await self._smb_call(smbclient.makedirs, self._path(root, rel), exist_ok=False)

    async def delete(self, root, rel):
        if not clean_path(rel):
            raise ValueError("Cannot delete mount root")
        item = await self.stat_file(root, rel)
        path = self._path(root, rel)
        await self._smb_call(smb_shutil.rmtree if item["is_dir"] else smbclient.remove, path)

    async def move(self, root, src_rel, dst_rel):
        self._validate_transfer(src_rel, dst_rel)
        if await self.exists(root, dst_rel):
            raise FileExistsError(dst_rel)
        await self._smb_call(smbclient.rename, self._path(root, src_rel), self._path(root, dst_rel))

    async def rename(self, root, src_rel, dst_rel):
        return await self.move(root, src_rel, dst_rel)

    async def copy(self, root, src_rel, dst_rel, overwrite=False):
        self._validate_transfer(src_rel, dst_rel)
        if await self.exists(root, dst_rel):
            if not overwrite:
                raise FileExistsError(dst_rel)
            await self.delete(root, dst_rel)
        source = self._path(root, src_rel)
        target = self._path(root, dst_rel)
        item = await self.stat_file(root, src_rel)
        if item["is_dir"]:
            await self._smb_call(smb_shutil.copytree, source, target)
        else:
            await self._smb_call(smbclient.makedirs, target.rsplit("\\", 1)[0], exist_ok=True)
            await self._smb_call(smb_shutil.copyfile, source, target)

    @staticmethod
    def _validate_transfer(src, dst):
        src, dst = clean_path(src), clean_path(dst)
        if not src or not dst or src == dst or dst.startswith(src + "/"):
            raise ValueError("Invalid transfer destination")


ADAPTER_TYPE = "smb"
ADAPTER_FACTORY = SMBAdapter
CONFIG_SCHEMA = [
    {"key": "server", "label": "Server", "type": "string", "required": True, "placeholder": "nas.example.com"},
    {"key": "share", "label": "Share name", "type": "string", "required": True},
    {"key": "port", "label": "Port", "type": "number", "default": 445},
    {"key": "guest", "label": "Guest access", "type": "boolean", "default": False},
    {"key": "username", "label": "Username", "type": "string", "required": False},
    {"key": "password", "label": "Password", "type": "password", "required": False},
    {"key": "root", "label": "Root directory", "type": "string", "default": "/"},
    {"key": "timeout", "label": "Timeout (seconds)", "type": "number", "default": 30},
]
