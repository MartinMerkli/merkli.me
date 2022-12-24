#!/usr/bin/env python3

# This is free and unencumbered software released into the public domain.

# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.

# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# For more information, please refer to <http://unlicense.org/>

from os.path import isdir, join, basename, getsize, exists
from os import listdir
from datetime import datetime
import zlib

backup_name = datetime.now().strftime('%Y-%m-%d_%H-%M')

max_file_size = 2147483648

directory = '/home/ubuntu/server/'
backup_directory = '/home/ubuntu/server/backups/'

exclude_names = ['__pycache__', 'venv', '.venv', '_venv', '_venv2', '_venv3', '~bromium', 'bromium', 'backups',
                 'recycle_bin']
exclude_extensions = ('.iso', '.exe', '.backup', '.pyc', '.db-journal')


def int_to_bytes(n):
    r = b''
    x = n
    while x > 0:
        r = bytes([x % 256]) + r
        x //= 256
    return r


def bytes_to_int(n):
    r = 0
    for p in n:
        r *= 256
        r += p
    return r


def write(data):
    global backup_directory, directory
    if (not isinstance(backup_directory, str)) or (not isinstance(directory, str)) or (not isinstance(data, bytes)):
        raise TypeError()
    for i in range(512):
        if len(data) == 0:
            return None
        cur_path = join(backup_directory, f"{backup_name}_{i}.backup")
        if exists(cur_path):
            if getsize(cur_path) + len(data) <= max_file_size:
                with open(cur_path, 'ab') as handler:
                    handler.write(data)
                return None
            else:
                free = max_file_size - getsize(cur_path)
                if free > 0:
                    with open(cur_path, 'ab') as handler:
                        handler.write(data[:free])
                    data = data[free:]
        else:
            if len(data) < max_file_size:
                with open(cur_path, 'ab') as handler:
                    handler.write(data)
                return None
            else:
                with open(cur_path, 'ab') as handler:
                    handler.write(data[:max_file_size])
                data = data[max_file_size:]
    raise RuntimeError()


def mass_read(path):
    r = b''
    for i in range(512):
        cur_path = f"{path}_{i}.backup"
        if exists(cur_path):
            with open(cur_path, 'rb') as f:
                r += f.read()
        else:
            return r


def get_indexed_files():
    global backup_directory, backup_name
    if not isinstance(backup_directory, str):
        raise TypeError()
    files = {}
    files2 = listdir(backup_directory)
    for i in files2:
        if not i.endswith('.backup'):
            files2.remove(i)
    files2.sort()
    files2.reverse()
    files3 = []
    for i in files2:
        if len(i) > len(backup_name):
            start = i[:len(backup_name)]
            if start not in files3:
                files3.append(start)
    files3.sort()
    for i in files3:
        content = mass_read(join(backup_directory, i))
        if content != b'':
            offset = 0
            while offset < len(content):
                name_length = bytes_to_int(content[offset:offset + 2])
                offset += 2
                name = content[offset:offset + name_length].decode('utf-8')
                offset += name_length
                data_length = bytes_to_int(content[offset:offset + 5])
                offset += 5
                data_hash = zlib.adler32(content[offset:offset + data_length])
                offset += data_length
                files[name] = data_hash
    return files


def main():
    global backup_directory, directory
    print(f"[{datetime.now().strftime('%Y-%m-%d_%H-%M')}] starting backup")
    indexed = get_indexed_files()
    files = []
    path = directory
    paths = listdir(path)
    while len(paths) > 0:
        path2 = join(path, paths[0])
        file = paths[0]
        del paths[0]
        if (basename(file).lower() not in exclude_names) and (not basename(file).lower().endswith(exclude_extensions)):
            if isdir(path2):
                for i in listdir(path2):
                    paths.append(join(file, i))
            else:
                files.append(file)
    for i, name in enumerate(files):
        with open(join(directory, name), 'rb') as f:
            data = zlib.compress(f.read(), level=9)
        if name in indexed:
            if zlib.adler32(data) == indexed[name]:
                continue
        data_length = int_to_bytes(len(data))
        name_length = int_to_bytes(len(name.encode('utf-8')))
        if len(name_length) > 2:
            raise OverflowError()
        while len(name_length) < 2:
            name_length = b'\x00' + name_length
        write(name_length)
        write(name.encode('utf-8'))
        if len(data_length) > 5:
            raise OverflowError()
        while len(data_length) < 5:
            data_length = b'\x00' + data_length
        write(data_length)
        write(data)
    print(f"[{datetime.now().strftime('%Y-%m-%d_%H-%M')}] finished backup")


if __name__ == '__main__':
    main()
