import argparse
import base64
import json
import os
import sys
import time
from loguru import logger
from Cryptodome.Cipher import AES


BASE64_ENCODING = "utf-8"
KEY_FILE = "aes_key"
META_FILE = "meta"


def write_meta(
    encrypted_path_segments: dict[str, str],
    encrypted_path_segments_aliases: dict[str, str],
    encrypted_path_to_file_content_tag: dict[str, str],
):
    logger.info("Writing meta started")

    with open(META_FILE, "w", encoding=BASE64_ENCODING) as out:
        json.dump(
            {
                "encrypted_path_segments": list(encrypted_path_segments),
                "encrypted_path_segments_aliases": encrypted_path_segments_aliases,
                "encrypted_path_to_file_content_tag": encrypted_path_to_file_content_tag,
            },
            out,
            indent=2,
            ensure_ascii=False,
        )
    logger.info("Writing meta finished")


def read_meta():
    with open(META_FILE, encoding=BASE64_ENCODING) as inp:
        meta = json.load(inp)
    return meta


def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode(BASE64_ENCODING).replace("/", "э")


def bytes_from_base64(data: str) -> bytes:
    return base64.b64decode(data.replace("э", "/").encode(BASE64_ENCODING))


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
            ciphertext = cipher.decrypt_and_verify(inp.read(), tag)
            out.write(ciphertext)
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


def encrypt_path(key: bytes, path: str, cache: dict[str,str]) -> tuple[str, list[str]]:
    logger.debug(f'Encrypting path "{path}" started')
    encrypted_path_segments = []
    tags = []
    for segment in path.split(os.sep):
        ciphertext, tag = encrypt_str(key, segment)
        encrypted_path_segments.append(bytes_to_base64(ciphertext))
        tags.append(bytes_to_base64(tag))
    logger.debug(f'Encrypting path "{path}" finished')
    for segment in encrypted_path_segments:
        if segment not in cache:
            cache[segment] = str(len(cache))
    return os.sep.join([cache[segment] for segment in encrypted_path_segments]), tags


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

    encrypted_path_segments = set()
    encrypted_path_to_file_content_tag = {}
    encrypted_path_segments_aliases = {}

    def save_path_segments(encrypted_path, tags):
        segments = encrypted_path.split(os.sep)
        for encrypted_segment, tag in zip(segments, tags):
            encrypted_path_segments.add((encrypted_segment, tag))

    for dirpath, subdirs, files in os.walk(dir):
        logger.info(f"Encrypting {dirpath}")

        encrypted_path, tags = encrypt_path(key, dirpath, encrypted_path_segments_aliases)
        save_path_segments(encrypted_path, tags)
        os.makedirs(encrypted_path, exist_ok=True)

        for subdir in subdirs:
            logger.debug(f'Processing subdir "{subdir}" of "{dirpath}" strated')
            full_path = os.path.join(dirpath, subdir)
            encrypted_full_path, tags = encrypt_path(key, full_path, encrypted_path_segments_aliases)
            save_path_segments(encrypted_full_path, tags)
            os.makedirs(encrypted_full_path)
            logger.debug(f'Processing subdir "{subdir}" of "{dirpath}" finished')

        for file in files:
            full_path = os.path.join(dirpath, file)
            logger.debug(f'Processing file "{file}" in "{full_path}" strated')
            encrypted_full_path, tags = encrypt_path(key, full_path, encrypted_path_segments_aliases)
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
    )


def decrypt(key: bytes):
    meta = read_meta()
    encrypted_path_segments_aliases = {v:k for k,v in meta['encrypted_path_segments_aliases'].items()}
    encrypted_path_segment_to_orig = {}
    for encrypted_path_segment_alias, tag in meta["encrypted_path_segments"]:
        encrypted_path_segment = encrypted_path_segments_aliases[encrypted_path_segment_alias]
        decrypted_path_segment = decrypt_str(key, bytes_from_base64(encrypted_path_segment), bytes_from_base64(tag))
        encrypted_path_segment_to_orig[encrypted_path_segment] = decrypted_path_segment
        logger.debug(
            f'Path segment decrypted: "{encrypted_path_segment}" -> "{decrypted_path_segment}"'
        )

    assert os.path.isdir('0'), f'There is no root dir ("0")'
    for dirpath, subdirs, files in os.walk("0"):
        os.makedirs(decrypt_path(dirpath, encrypted_path_segment_to_orig, encrypted_path_segments_aliases), exist_ok=True)
        for subdir in subdirs:
            full_path = os.path.join(dirpath, subdir)
            os.makedirs(decrypt_path(full_path, encrypted_path_segment_to_orig, encrypted_path_segments_aliases), exist_ok=True)
        for file in files:
            full_path = os.path.join(dirpath, file)
            tag = meta["encrypted_path_to_file_content_tag"][full_path]
            decrypt_file(key, bytes_from_base64(tag), full_path, decrypt_path(full_path, encrypted_path_segment_to_orig, encrypted_path_segments_aliases))


def parse_arguments():
    parser = argparse.ArgumentParser(description="A script that encrypts a folder.")

    parser.add_argument(
        "--folder",
        type=str,
        required=False,
        help="Path to the folder that needs to be encrypted or decrypted",
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
    print(args)
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    logger.add(f"file_{time.strftime('%Y-%m-%d')}.log", rotation="512Mb", level=args.log_level)
    logger.debug("DEBUG LEVEL LOGS ARE VERY UNSAFE, PLEASE, SECURE YOUR LOGS WELL")

    assert os.path.isfile(KEY_FILE), f'There is not "{KEY_FILE}" file'

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
