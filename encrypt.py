import argparse
import base64
import json
import os
import sys
import time
import hashlib
import shutil
from loguru import logger
from Cryptodome.Cipher import AES

BASE64_ENCODING = "utf-8"
KEY_FILE = "aes_key"
META_FILE = "meta.json"

def get_aes_key_hash(aes_key: bytes) -> str:
    return hashlib.sha256(aes_key).hexdigest()

def write_meta(
    encrypted_path_segments: list, # list of [alias, tag]
    encrypted_path_segments_aliases: dict[str, str],
    encrypted_path_to_file_content_tag: dict[str, str],
    aes_key: bytes,
    root_alias: str
):
    logger.info("Writing meta started")
    data = {
        "encrypted_path_segments": encrypted_path_segments,
        "encrypted_path_segments_aliases": encrypted_path_segments_aliases,
        "encrypted_path_to_file_content_tag": encrypted_path_to_file_content_tag,
        "aes_key_hash": get_aes_key_hash(aes_key),
        "root_alias": root_alias
    }
    
    with open(META_FILE, "w", encoding=BASE64_ENCODING) as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
    logger.info("Writing meta finished")

def read_meta(should_exist: bool = True):
    if not os.path.exists(META_FILE):
        if should_exist:
            logger.error(f"Meta file {META_FILE} not found!")
            sys.exit(1)
        return None
        
    with open(META_FILE, encoding=BASE64_ENCODING) as inp:
        return json.load(inp)

def bytes_to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode(BASE64_ENCODING)

def bytes_from_base64(data: str) -> bytes:
    return base64.b64decode(data.encode(BASE64_ENCODING))

def encrypt_bytes(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    # SIV mode: deterministic. Good for git diffs, bad for pattern hiding.
    cipher = AES.new(key, AES.MODE_SIV)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def decrypt_bytes(key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_SIV)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_file(key: bytes, source_path: str, destination_path: str) -> bytes:
    logger.debug(f"Encrypting file {source_path} -> {destination_path}")
    with open(source_path, "rb") as inp:
        data = inp.read()
    
    ciphertext, tag = encrypt_bytes(key, data)
    
    with open(destination_path, "wb") as out:
        out.write(ciphertext)
    
    return tag

def decrypt_file(key: bytes, tag: bytes, source_path: str, destination_path: str):
    with open(source_path, "rb") as inp:
        ciphertext = inp.read()
    
    plaintext = decrypt_bytes(key, ciphertext, tag)
    
    with open(destination_path, "wb") as out:
        out.write(plaintext)

def encrypt_str(key: bytes, data: str) -> tuple[str, str]:
    # Returns (b64_ciphertext, b64_tag)
    ct, tag = encrypt_bytes(key, data.encode("utf-8"))
    return bytes_to_base64(ct), bytes_to_base64(tag)

def decrypt_str(key: bytes, b64_ct: str, b64_tag: str) -> str:
    ct = bytes_from_base64(b64_ct)
    tag = bytes_from_base64(b64_tag)
    return decrypt_bytes(key, ct, tag).decode("utf-8")

def get_path_segments(path: str):
    return [p for p in path.split(os.sep) if p]

def encrypt(key: bytes, source_dir: str):
    source_dir = os.path.abspath(source_dir)
    parent_dir = os.path.dirname(source_dir)
    
    logger.info(f"Encrypting {source_dir}, relative to {parent_dir}")

    encrypted_path_segments_set = set() # Using set to avoid duplicates
    encrypted_path_to_file_content_tag = {}
    encrypted_path_segments_aliases = {} 

    # Restore mapping if key matches
    meta = read_meta(should_exist=False)
    if meta and meta.get("aes_key_hash") == get_aes_key_hash(key):
        logger.info("Key matched, restoring previous path aliases to minimize diff")
        for enc_seg, alias in meta["encrypted_path_segments_aliases"].items():
            encrypted_path_segments_aliases[enc_seg] = alias
    else:
        if meta: logger.warning("Key changed or no meta. Full rewrite.")

    def get_alias_for_segment(segment_str: str) -> str:
        enc_seg, tag = encrypt_str(key, segment_str)
        encrypted_path_segments_set.add((enc_seg, tag))
        
        if enc_seg not in encrypted_path_segments_aliases:
            new_id = str(len(encrypted_path_segments_aliases))
            encrypted_path_segments_aliases[enc_seg] = new_id
            
        return encrypted_path_segments_aliases[enc_seg]

    root_folder_name = os.path.basename(source_dir)
    root_alias = get_alias_for_segment(root_folder_name)
    
    os.makedirs(root_alias, exist_ok=True)

    for dirpath, subdirs, files in os.walk(source_dir):
        rel_path = os.path.relpath(dirpath, parent_dir)
        segments = get_path_segments(rel_path)
        
        path_aliases = [get_alias_for_segment(seg) for seg in segments]
        encrypted_dir_path = os.path.join(*path_aliases)
        
        os.makedirs(encrypted_dir_path, exist_ok=True)

        for file in files:
            file_path = os.path.join(dirpath, file)
            file_rel_path = os.path.join(rel_path, file) # Путь включая корень
            
            file_segments = get_path_segments(file_rel_path)
            file_path_aliases = [get_alias_for_segment(seg) for seg in file_segments]
            encrypted_file_path = os.path.join(*file_path_aliases)
            
            tag = encrypt_file(key, file_path, encrypted_file_path)
            
            encrypted_path_to_file_content_tag[encrypted_file_path] = bytes_to_base64(tag)

    write_meta(
        encrypted_path_segments=list(encrypted_path_segments_set),
        encrypted_path_segments_aliases=encrypted_path_segments_aliases,
        encrypted_path_to_file_content_tag=encrypted_path_to_file_content_tag,
        aes_key=key,
        root_alias=root_alias
    )
    logger.success(f"Encryption finished. Root alias is '{root_alias}'")


def decrypt(key: bytes):
    meta = read_meta()
    
    # Восстанавливаем обратный маппинг: Alias -> DecryptedString
    alias_to_decrypted = {}
    
    # Сначала маппинг Alias -> (EncryptedSeg, Tag)
    # В мете segments это список [enc, tag]. aliases это dict enc -> alias
    # Нам нужно быстро по алиасу найти параметры для расшифровки
    
    # Создадим lookup для тегов сегментов
    enc_seg_to_tag = {item[0]: item[1] for item in meta["encrypted_path_segments"]}
    
    for enc_seg, alias in meta["encrypted_path_segments_aliases"].items():
        tag = enc_seg_to_tag.get(enc_seg)
        if not tag:
            logger.error(f"Integrity error: Alias {alias} has no tag in segments list")
            continue
        decrypted_segment = decrypt_str(key, enc_seg, tag)
        alias_to_decrypted[alias] = decrypted_segment

    root_alias = meta.get("root_alias")
    if not root_alias:
        # Fallback для старых версий или если сломано, но лучше упасть
        logger.error("Root alias not found in meta!")
        exit(1)

    if not os.path.isdir(root_alias):
        logger.error(f"Root encrypted directory '{root_alias}' not found. Are you in the right folder?")
        sys.exit(1)

    root_decrypted_name = alias_to_decrypted[root_alias]
    
    # Бэкап если существует
    if os.path.exists(root_decrypted_name):
        backup_name = f"{root_decrypted_name}_backup_{time.strftime('%Y%m%d_%H%M%S')}"
        logger.warning(f"Output directory {root_decrypted_name} exists. Backing up to {backup_name}")
        shutil.move(root_decrypted_name, backup_name)

    for dirpath, subdirs, files in os.walk(root_alias):
        # dirpath это путь из алиасов, например "0/5/2"
        
        # Восстанавливаем путь
        path_parts = get_path_segments(dirpath)
        try:
            decrypted_parts = [alias_to_decrypted[p] for p in path_parts]
        except KeyError as e:
            logger.error(f"Unknown alias in path {dirpath}: {e}. Skipping.")
            continue
            
        dest_dir = os.path.join(*decrypted_parts)
        os.makedirs(dest_dir, exist_ok=True)
        
        for file in files:
            encrypted_file_full_path = os.path.join(dirpath, file)
            
            # Расшифровываем имя файла
            file_alias = file
            if file_alias not in alias_to_decrypted:
                 logger.warning(f"Unknown file alias {file_alias} in {dirpath}")
                 continue
            
            decrypted_filename = alias_to_decrypted[file_alias]
            dest_file_path = os.path.join(dest_dir, decrypted_filename)
            
            # Ищем тег контента
            content_tag_b64 = meta["encrypted_path_to_file_content_tag"].get(encrypted_file_full_path)
            if not content_tag_b64:
                logger.warning(f"No content tag for {encrypted_file_full_path}. Skipping content.")
                continue
                
            try:
                decrypt_file(key, bytes_from_base64(content_tag_b64), encrypted_file_full_path, dest_file_path)
            except Exception as e:
                logger.error(f"Failed to decrypt file {dest_file_path}: {e}")

    logger.success("Decryption finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", type=str, help="Folder to encrypt")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt mode")
    args = parser.parse_args()

    logger.remove()
    logger.add(sys.stderr, level="INFO")

    if not os.path.exists(KEY_FILE):
        logger.error(f"Key file '{KEY_FILE}' not found.")
        sys.exit(1)

    with open(KEY_FILE, "rb") as f:
        key = f.read()

    if args.decrypt:
        decrypt(key)
    else:
        if not args.folder:
            logger.error("Provide --folder to encrypt")
            sys.exit(1)
        encrypt(key, args.folder)