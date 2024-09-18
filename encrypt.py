import argparse
import base64
import json
import os
import sys
import time
import hashlib
from loguru import logger
from Cryptodome.Cipher import AES


BASE64_ENCODING = "utf-8"
KEY_FILE = "aes_key"
META_FILE = "meta"
ENCRYPTED_ROOT_DIR = "0"


def get_aes_key_hash(aes_key: bytes) -> str:
    logger.debug("Calculating aes key hash")
    hasher = hashlib.sha256()
    bytes_to_hash = max(
        int(len(aes_key) / 4), 2
    )  # don't want to allow bruteforce attack via sha256
    to_hash = (
        aes_key[: int(bytes_to_hash / 2)]
        + aes_key[int(len(aes_key) / 2) : int(len(aes_key) / 2) + int(bytes_to_hash / 2)]
    ) # because aes_siv splits key into 2 parts https://github.com/Legrandin/pycryptodome/blob/d470020d85ce9a15a07787ef5449df157abd8d0f/lib/Crypto/Cipher/_mode_siv.py#L114
    hasher.update(to_hash)
    hash = hasher.hexdigest()
    logger.debug(f'Aes key hash is "{hash}"')
    return hash


def write_meta(
    encrypted_path_segments: dict[str, str],
    encrypted_path_segments_aliases: dict[str, str],
    encrypted_path_to_file_content_tag: dict[str, str],
    aes_key: bytes,
):
    logger.info("Writing meta started")

    with open(META_FILE, "w", encoding=BASE64_ENCODING) as out:
        json.dump(
            {
                "encrypted_path_segments": list(encrypted_path_segments),
                "encrypted_path_segments_aliases": encrypted_path_segments_aliases,
                "encrypted_path_to_file_content_tag": encrypted_path_to_file_content_tag,
                "aes_key_hash": get_aes_key_hash(aes_key),
            },
            out,
            indent=2,
            ensure_ascii=False,
        )
    logger.info("Writing meta finished")


def read_meta(should_exist: bool = True):
    logger.info(f'Try to read meta from "{META_FILE}", should_exists "{should_exist}"')
    if not should_exist:
        if not os.path.exists(META_FILE):
            logger.debug(f'Can\'t read meta: "{META_FILE}" does not exist.')
            return None
    with open(META_FILE, encoding=BASE64_ENCODING) as inp:
        meta = json.load(inp)
    logger.info("Meta has been read")
    return meta


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode(BASE64_ENCODING)


def bytes_from_base64(data: str) -> bytes:
    return base64.b64decode(data.encode(BASE64_ENCODING))


def encrypt_file(key: bytes, source_path: str, destination_path: str) -> bytes:
    logger.debug(
        f'Encrypting file "{source_path}" started. Destination is "{destination_path}"'
    )
    cipher = AES.new(key, AES.MODE_SIV)
    assert os.path.isfile(source_path), f'"{source_path}" is not a file'
    if os.path.exists(destination_path):
        logger.warning(f'Overwriting "{destination_path}"')
    with open(source_path, "rb") as inp:
        with open(destination_path, "wb") as out:
            ciphertext, tag = cipher.encrypt_and_digest(inp.read())
            out.write(ciphertext)
    logger.debug(
        f'Encrypting file "{source_path}" finished. Destination is "{destination_path}"'
    )
    return tag


def decrypt_file(
    key: bytes, tag: bytes, source_path: str, destination_path: str
) -> bytes:
    logger.debug(
        f'Decrypting file "{source_path}" started. Destination is "{destination_path}"'
    )

    cipher = AES.new(key, AES.MODE_SIV)
    assert os.path.isfile(source_path), f'"{source_path}" is not a file'
    if os.path.exists(destination_path):
        logger.warning(f'Overwriting "{destination_path}"')
    with open(source_path, "rb") as inp:
        with open(destination_path, "wb") as out:
            plain_text = cipher.decrypt_and_verify(inp.read(), tag)
            out.write(plain_text)
    logger.debug(
        f'Decrypting file "{source_path}" finished. Destination is "{destination_path}"'
    )


def encrypt_str(key: bytes, data: str, encoding: str = "utf-8") -> tuple[bytes, bytes]:
    logger.debug(f'Encrypting str "{data}" started')
    assert isinstance(data, str), f'"{data}" is not str, it is "{type(data)}"'
    cipher = AES.new(key, AES.MODE_SIV)
    try:
        data_as_bytes = data.encode(encoding)
    except Exception as e:
        logger.exception(f'Can\'t encode data "{data}" as "{encoding}"')
        raise e
    ciphertext, tag = cipher.encrypt_and_digest(data_as_bytes)
    logger.debug(f'Encrypting str "{data}" finished')
    return ciphertext, tag


def decrypt_str(key: bytes, data: bytes, tag: bytes, encoding: str = "utf-8") -> str:
    logger.debug(f"Decrypting bytes started")
    assert isinstance(data, bytes), f'"data" is not bytes, it is "{type(data)}"'
    cipher = AES.new(key, AES.MODE_SIV)
    decrypted_bytes = cipher.decrypt_and_verify(data, tag)
    try:
        res = decrypted_bytes.decode(encoding)
    except Exception as e:
        logger.exception(f'Can\'t decode bytes "{decrypted_bytes}" as "{encoding}"')
        raise e
    logger.debug(f"Decrypting bytes finished")
    return res


def encrypt_path(
    key: bytes, path: str, known_pathes_mapping: dict[str, str], relative_to: str = None
) -> tuple[str, list[str]]:
    logger.debug(f'Encrypting path "{path}" started')
    if relative_to is not None:
        path = os.path.relpath(path, relative_to)
    encrypted_path_segments = []
    tags = []
    for segment in path.split(os.sep):
        ciphertext, tag = encrypt_str(key, segment)
        encrypted_path_segments.append(bytes_to_base64(ciphertext))
        tags.append(bytes_to_base64(tag))
    logger.debug(f'Encrypting path "{path}" finished')

    for segment in encrypted_path_segments:
        if segment not in known_pathes_mapping:
            logger.debug(
                f'Adding known_pathes_mapping [{segment}] -> "{str(len(known_pathes_mapping))}"'
            )
            known_pathes_mapping[segment] = str(len(known_pathes_mapping))
    return (
        os.sep.join(
            [known_pathes_mapping[segment] for segment in encrypted_path_segments]
        ),
        tags,
    )


def decrypt_path(
    encrypted_path: str,
    encrypted_path_segment_to_original: dict[str, str],
    encrypted_path_segments_aliases: dict[str, str],
) -> str:
    logger.debug(f'Decrypting path "{encrypted_path}" started')
    decrypted_path_segments = []

    for segment in encrypted_path.split(os.sep):
        segment = encrypted_path_segments_aliases[segment]
        assert (
            segment in encrypted_path_segment_to_original
        ), f'Segment "{segment}" is not in encrypted_path_segment_to_original'
        decrypted_path_segments.append(encrypted_path_segment_to_original[segment])
    res = os.sep.join(decrypted_path_segments)
    logger.debug(
        f'Decrypting path "{encrypted_path}" finished, res is "{os.sep.join(decrypted_path_segments)}"'
    )
    return res


def encrypt(key: bytes, dir: str):

    dir = dir.rstrip(os.sep)
    parent_dir = os.path.dirname(dir)
    encrypted_path_segments = set()
    encrypted_path_to_file_content_tag = {}
    encrypted_path_segments_aliases = {}

    if (meta := read_meta(should_exist=False)) is not None:
        if meta.get("aes_key_hash") == get_aes_key_hash(key):
            logger.info("Same key detected, restoring path parts mapping")
            encrypted_path_segments_aliases = {
                encrypted_name: alias
                for encrypted_name, alias in meta[
                    "encrypted_path_segments_aliases"
                ].items()
            }  # have to restore the exact mapping to prevent the encrypted name from changing, because this will lead to unnecessarily large commits.
            logger.debug(
                f'"encrypted_path_segments_aliases" {encrypted_path_segments_aliases}'
            )

    def save_path_segments(encrypted_path, tags):
        segments = encrypted_path.split(os.sep)
        for encrypted_segment, tag in zip(segments, tags):
            encrypted_path_segments.add((encrypted_segment, tag))

    for dirpath, subdirs, files in os.walk(dir):
        logger.info(f"Encrypting {dirpath}")

        encrypted_path, tags = encrypt_path(
            key, dirpath, encrypted_path_segments_aliases, relative_to=parent_dir
        )
        save_path_segments(encrypted_path, tags)
        os.makedirs(encrypted_path, exist_ok=True)

        for subdir in subdirs:
            logger.debug(f'Processing subdir "{subdir}" of "{dirpath}" strated')
            full_path = os.path.join(dirpath, subdir)
            encrypted_full_path, tags = encrypt_path(
                key, full_path, encrypted_path_segments_aliases, relative_to=parent_dir
            )
            save_path_segments(encrypted_full_path, tags)
            os.makedirs(encrypted_full_path)
            logger.debug(f'Processing subdir "{subdir}" of "{dirpath}" finished')

        for file in files:
            full_path = os.path.join(dirpath, file)
            logger.debug(f'Processing file "{file}" in "{full_path}" strated')
            encrypted_full_path, tags = encrypt_path(
                key, full_path, encrypted_path_segments_aliases, relative_to=parent_dir
            )
            save_path_segments(encrypted_full_path, tags)
            tag = encrypt_file(key, full_path, encrypted_full_path)
            assert encrypted_full_path not in encrypted_path_to_file_content_tag
            encrypted_path_to_file_content_tag[encrypted_full_path] = bytes_to_base64(
                tag
            )
            logger.debug(f'Processing file "{file}" in "{full_path}" finished')

    write_meta(
        encrypted_path_segments=encrypted_path_segments,
        encrypted_path_segments_aliases=encrypted_path_segments_aliases,
        encrypted_path_to_file_content_tag=encrypted_path_to_file_content_tag,
        aes_key=key,
    )


def decrypt(key: bytes):
    meta = read_meta()
    encrypted_path_segments_aliases = {
        v: k for k, v in meta["encrypted_path_segments_aliases"].items()
    }
    encrypted_path_segment_to_orig = {}
    for encrypted_path_segment_alias, tag in meta["encrypted_path_segments"]:
        encrypted_path_segment = encrypted_path_segments_aliases[
            encrypted_path_segment_alias
        ]
        decrypted_path_segment = decrypt_str(
            key, bytes_from_base64(encrypted_path_segment), bytes_from_base64(tag)
        )
        encrypted_path_segment_to_orig[encrypted_path_segment] = decrypted_path_segment
        logger.debug(
            f'Path segment decrypted: "{encrypted_path_segment}" -> "{decrypted_path_segment}"'
        )

    assert os.path.isdir(
        ENCRYPTED_ROOT_DIR
    ), f'There is no root dir ("{ENCRYPTED_ROOT_DIR}")'
    root_dir_name = decrypt_path(
        ENCRYPTED_ROOT_DIR,
        encrypted_path_segment_to_orig,
        encrypted_path_segments_aliases,
    )
    if os.path.exists(root_dir_name):
        backup_name = f"{root_dir_name}_backup_{time.strftime('%Y-%m-%d_%H:%M:%S')}"
        logger.info(f'Found "{root_dir_name}", creating backup "{backup_name}".')

        import shutil

        if os.path.isdir(root_dir_name):
            shutil.copytree(root_dir_name, backup_name)
        elif os.path.isfile(root_dir_name):
            shutil.copy2(root_dir_name, backup_name)
        else:
            logger.error(
                f"{root_dir_name} already exists. It has the same name as the root directory of decrypted data but it's not a file of directory. Remove or rename it."
            )
    for dirpath, subdirs, files in os.walk(ENCRYPTED_ROOT_DIR):
        os.makedirs(
            decrypt_path(
                dirpath, encrypted_path_segment_to_orig, encrypted_path_segments_aliases
            ),
            exist_ok=True,
        )
        for subdir in subdirs:
            full_path = os.path.join(dirpath, subdir)
            os.makedirs(
                decrypt_path(
                    full_path,
                    encrypted_path_segment_to_orig,
                    encrypted_path_segments_aliases,
                ),
                exist_ok=True,
            )
        for file in files:
            full_path = os.path.join(dirpath, file)
            tag = meta["encrypted_path_to_file_content_tag"][full_path]
            decrypt_file(
                key,
                bytes_from_base64(tag),
                full_path,
                decrypt_path(
                    full_path,
                    encrypted_path_segment_to_orig,
                    encrypted_path_segments_aliases,
                ),
            )


def parse_arguments():
    parser = argparse.ArgumentParser(description="A script that encrypts a folder.")

    parser.add_argument(
        "--folder",
        type=str,
        required=False,
        help="Path to the folder to encrypt",
    )

    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt the folder instead of encrypting.",
    )

    parser.add_argument(
        "--log_level",
        type=str,
        default="INFO",
        choices=["INFO", "DEBUG"],
        help="Logging level (default: INFO)",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    logger.debug(args)
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    logger.add(
        f"file_{time.strftime('%Y-%m-%d')}.log", rotation="512Mb", level=args.log_level
    )
    logger.info(
        "LOGS MAY CONTAIN VERY SENSITIVE INFORMATION. PLEASE, SECURE YOUR LOGS WELL"
    )

    assert os.path.isfile(KEY_FILE), f'There is no "{KEY_FILE}" file'
    if not args.decrypt:
        assert os.path.isdir(args.folder), f'"{args.folder}" is not a directory'

    with open(KEY_FILE, "rb") as inp:
        key = inp.read()
        try:
            AES.new(key, AES.MODE_SIV)
        except Exception as e:
            logger.exception(f'Key "{KEY_FILE}" is not ok.')
            raise e

    if not args.decrypt:
        encrypt(key, args.folder)
    else:
        decrypt(key)
