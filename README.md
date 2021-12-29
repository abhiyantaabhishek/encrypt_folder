# encrypt_folder
## cryptography wrapper for encryting whole folder
The script can encrypt (symmetric encryption) whole folder to a single hdf5 file and can decrypt it back to the floder. Either password or a key file can be used for encrytion and decrytion.

## Uses:
### Using  password
same password should be used for encryption and decryption
> Encrypt
```bash
python cryptography_wrapper.py encrypt "folder/to/encrypt" "path/to/save/encrypted.h5" -p "your_password"
```
Example:
```bash
python cryptography_wrapper.py encrypt "D:\abhi\cryptography\to_encrypt" "D:\abhi\cryptography\encrypted.h5" -p "my_password"
```
>  Decrypt
```bash
python cryptography_wrapper.py decrypt "path/of/encrypted.h5" "path/to/save/decrypted/floder" -p "your_password"
```
Example:
```bash
python cryptography_wrapper.py decrypt "D:\abhi\cryptography\encrypted.h5" "D:\abhi\cryptography\decrypted" -p "my_password"
```
### Using  Key
To use key, the key file must be generated using below commnand, same key should be used for encryption and decryption
> Generate key
```bash
python cryptography_wrapper.py gen_key  "path/to/key.key"
```
Example:
```bash
python cryptography_wrapper.py gen_key "D:\abhi\cryptography\key.key"
```
> Encrypt
```bash
python cryptography_wrapper.py encrypt "folder/to/encrypt" "path/to/save/encrypted.h5"  -kp "path/to/key.key"
```
Example:
```bash
python cryptography_wrapper.py encrypt "D:\abhi\cryptography\to_encrypt" "D:\abhi\cryptography\encrypted.h5" -kp "D:\abhi\cryptography\key.key"
```
>  Decrypt
```bash
python cryptography_wrapper.py decrypt "path/of/encrypted.h5" "path/to/save/decrypted/floder" -kp "path/to/key.key"
```
Example:
```bash
python cryptography_wrapper.py decrypt "D:\abhi\cryptography\encrypted.h5" "D:\abhi\cryptography\decrypted" -kp "D:\abhi\cryptography\key.key"
```
