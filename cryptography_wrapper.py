# %%
import argparse
import os
import h5py
import json
import base64
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# %%


def gen_key_from_password(password):
    password = password.encode()
    salt = b"randomAndStrongSalt"  # Same salt sould be used everytime to generate key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def gen_key(key_path):
    key = Fernet.generate_key()
    Path(key_path).write_bytes(key)
    return


def load_key(key_path):
    key = Path(key_path).read_bytes()
    return key


def get_file_name_map(input_dir):
    f_ctr = 2
    d_ctr = 2
    file_name_map = {}
    dir_name_map = {}
    for files in input_dir.glob("**/*"):
        if files.is_file():
            file_name_map["layer_" + str(f_ctr)] = files.relative_to(
                input_dir
            ).as_posix()
            f_ctr += 1
        if files.is_dir():
            dir_name_map["layer_d" + str(d_ctr)] = files.relative_to(
                input_dir
            ).as_posix()
            d_ctr += 1
    return file_name_map, dir_name_map


def encode_and_encrypt_json(name_map, fernet_obj):
    encoded_name_map = json.dumps(name_map, indent=2).encode("utf-8")
    encrypted = fernet_obj.encrypt(encoded_name_map)
    return encrypted


def encrypt_dir_toh5(input_dir, output_h5, key):
    fernet_obj = Fernet(key)
    file_name_map, dir_name_map = get_file_name_map(input_dir)
    hf = h5py.File(output_h5, "w")
    hf.create_dataset(
        "layer_" + "0", data=encode_and_encrypt_json(dir_name_map, fernet_obj)
    )
    hf.create_dataset(
        "layer_" + "1", data=encode_and_encrypt_json(file_name_map, fernet_obj)
    )
    for hdf_key, val in file_name_map.items():
        file_path = input_dir / Path(val)
        if file_path.is_file():
            encrypted = fernet_obj.encrypt(file_path.read_bytes())
            hf.create_dataset(hdf_key, data=encrypted)
    hf.close()
    print(
        "The directory is encrypted successfully, keep the key safe to decode it later"
    )


def decrypt_and_decode_json(hf, fernet_obj, layer):
    encrypted = hf.get(layer)[()]
    try:
        decrypted = fernet_obj.decrypt(encrypted)
    except InvalidToken as e:
        print("Invalid Key, Try again with a valid key ... ")
        return
    decoded_name_map = json.loads(decrypted.decode("utf-8"))
    return decoded_name_map


def decrypt_dir_from_h5(input_h5, output_dir, key):
    hf = h5py.File(input_h5, "r")
    fernet_obj = Fernet(key)
    decoded_dir_name_map = decrypt_and_decode_json(hf, fernet_obj, "layer_0")
    decoded_file_name_map = decrypt_and_decode_json(hf, fernet_obj, "layer_1")
    for hdf_key, val in decoded_dir_name_map.items():
        dest_file_name = Path(val)
        dest_file_name = output_dir / dest_file_name
        dest_file_name.mkdir(parents=True, exist_ok=True)
    for hdf_key, val in decoded_file_name_map.items():
        dest_file_name = Path(val)
        dest_file_name = output_dir / dest_file_name
        encrypted = hf.get(hdf_key)[()]
        try:
            decrypted = fernet_obj.decrypt(encrypted)
        except InvalidToken as e:
            print("Invalid Key, Try again with a  Valid key ... ")
            return
        dest_file_name.write_bytes(decrypted)
    hf.close()
    print("The directory is decrypted successfully")


# %%

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="help for subcommand", dest="command")

    parser_a = subparsers.add_parser(
        "encrypt",
        help="encrypt input_dir output.h5 -p your_password OR encrypt input_dir output.h5 -lk path/to/key.key ",
    )
    parser_a.add_argument("input", type=str)
    parser_a.add_argument("output", type=str)
    mutually_exclusive_a = parser_a.add_argument_group()
    group_a = mutually_exclusive_a.add_mutually_exclusive_group(required=True)
    group_a.add_argument("-p", "--password")
    group_a.add_argument("-kp", "--key_path")

    parser_b = subparsers.add_parser(
        "decrypt",
        help="decrypt input.h5 output_dir -p your_password OR decrypt input.h5 output_dir -lk path/to/key.key",
    )
    parser_b.add_argument("input", type=str)
    parser_b.add_argument("output", type=str)
    mutually_exclusive_b = parser_b.add_argument_group()
    group_b = mutually_exclusive_b.add_mutually_exclusive_group(required=True)
    group_b.add_argument("-p", "--password")
    group_b.add_argument("-kp", "--key_path")

    parser_c = subparsers.add_parser("gen_key", help="gen_key  path/to/key.key")
    parser_c.add_argument("key_path", type=str)
    args = parser.parse_args()
    if args.command == "encrypt":
        if args.password != None:
            key = gen_key_from_password(args.password)
        else:
            key = load_key(args.key_path)
        encrypt_dir_toh5(Path(args.input), args.output, key)
    elif args.command == "decrypt":
        if args.password != None:
            key = gen_key_from_password(args.password)
        else:
            key = load_key(args.key_path)
        decrypt_dir_from_h5(args.input, Path(args.output), key)
    elif args.command == "gen_key":
        gen_key(args.key_path)


#%%
# python cryptography_wrapper.py encrypt "D:\abhi\cryptography\to_encrypt" "D:\abhi\cryptography\encrypted.h5" -p "my_password"
# python cryptography_wrapper.py decrypt "D:\abhi\cryptography\encrypted.h5" "D:\abhi\cryptography\decrypted" -p "my_password"

# python cryptography_wrapper.py gen_key "D:\abhi\cryptography\key.key"
# python cryptography_wrapper.py encrypt "D:\abhi\cryptography\to_encrypt" "D:\abhi\cryptography\encrypted.h5" -kp "D:\abhi\cryptography\key.key"
# python cryptography_wrapper.py decrypt "D:\abhi\cryptography\encrypted.h5" "D:\abhi\cryptography\decrypted" -kp "D:\abhi\cryptography\key.key"
