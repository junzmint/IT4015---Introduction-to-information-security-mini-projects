from os import urandom
import zlib

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2
def bit_likes_to_hexa(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)])for i in range(0, len(b), 8)])

class IntegrityViolation(Exception):
    pass


def generate_keys(seed_text, salt):
    # Em dùng thuật toán PBKDF2 để tạo ra encryption and hmac key
    full_key = PBKDF2(seed_text, salt, dkLen=64, count=1345)

    # Để mã hóa bản rõ trong file log. encrypt_key có độ dài 256 bit
    encrypt_key = full_key[:int(len(full_key) / 2)]

    hmac_key = full_key[int(len(full_key) / 2):]

    return encrypt_key, hmac_key



def write_logfile(log_filename, auth_token, logfile_pt):
    # Compress cái file log chứa bản mã
    logfile_pt = zlib.compress(logfile_pt, 5)

    # Sinh encryption và hmac keys
    rand_salt = urandom(16)
    logfile_ct = rand_salt
    encrypt_key, hmac_key = generate_keys(auth_token, rand_salt)

    # Cài đặt counter cho AES CTR-mode 
    ctr_iv = urandom(16) # Khối AES counter độ lớn 128 bit (16 byte)
    ctr = Counter.new(128, initial_value=int(bit_likes_to_hexa(ctr_iv), 16))
    logfile_ct = logfile_ct + ctr_iv

    # Tạo ra object AES
    cipher = AES.new(encrypt_key, AES.MODE_CTR, counter=ctr)

    # Mã hóa bản rõ và in vào file log chứa IV cho AES CTR
    logfile_ct = logfile_ct + cipher.encrypt(logfile_pt)

    # Sử dụng nửa thứ 2 của token gán cho bản mã của file log sử dụng MAC (message authentication code)
    hmac_obj = HMAC.new(hmac_key, logfile_ct, SHA256)
    mac = hmac_obj.digest()

    # Gán MAC cho file log
    logfile_ct = logfile_ct + mac

    # Tạo file trong bộ nhớ
    # Mở file bằng cách mở file nhị phân
    with open(log_filename, 'wb') as f:
        f.write(logfile_ct)

    return None


def read_logfile(log_filename, auth_token):
    # Đọc từ file log dùng chế độ nhị phân
    with open(log_filename, 'rb') as f:
        logfile_ct = f.read()

    # Lấy hmac từ file
    hmac_salt = logfile_ct[:16]

    # Sinh encryption và hmac key từ token
    encrypt_key, hmac_key = generate_keys(auth_token, hmac_salt)

    # Đặt độ dài của MAC
    mac_length = 32

    # Lấy MAC từ cuối file
    mac = logfile_ct[-mac_length:]

    # Cắt cái MAC từ cuối file
    logfile_ct = logfile_ct[:-mac_length]

    # Kiểm tra MAC
    hmac_obj = HMAC.new(hmac_key, logfile_ct, SHA256)
    computed_mac = hmac_obj.digest()

    if computed_mac != mac:
        # Nếu MAC k đúng thì thông báo lỗi để sửa chữa
        raise IntegrityViolation()

    # Cắt hmac từ đầu file
    logfile_ct = logfile_ct[16:]

    # LẤy lại IV từ bản mã
    ctr_iv = logfile_ct[:16]  # AES counter có độ lớn 128 bit (16 byte)

    # Cắt IV khỏi bản mã
    logfile_ct = logfile_ct[16:]

    # Khởi tạo counter
    ctr = Counter.new(128, initial_value=int(bit_likes_to_hexa(ctr_iv), 16))

    # Tạo AES object và giải mã
    cipher = AES.new(encrypt_key, AES.MODE_CTR, counter=ctr)
    logfile_pt = cipher.decrypt(logfile_ct)

    # Decompress file log chứa bản mã
    logfile_pt = zlib.decompress(logfile_pt)

    return logfile_pt


if __name__ == "__main__":

    filename = 'encrypted.dat'

    plain_text = ("If thou'lt be mine, the treasures of air\nOf earth, and sea, shall lie at thy feet\nWhatever in Fancy's eye looks fair\nOr in Hope's sweet music sounds most sweet\nShall be ours — if thou wilt be mine, love!\nBright flowers shall bloom wherever we rove\nA voice divine shall talk in each stream\nThe stars shall look like world of love\nAnd this earth be all one beautiful dream\nIn our eyes — if thou wilt be mine, love!")

    token = "IfThou'ltBeMine"

    #Gọi các hàm
    try:
        write_logfile(filename, token, plain_text.encode())
    except EnvironmentError:
        print ("Error writing file to disk")
        raise SystemExit(5)
    except ValueError:
        print ("ValueError exception raised")
        raise SystemExit(2)

    try:
        recovered_plain_text = read_logfile(filename, token)
    except EnvironmentError:
        print ("Error reading file from disk")
        raise SystemExit(5)
    except IntegrityViolation:
        print ("Error authenticating the encrypted file")
        raise SystemExit(9)

    try:
        assert (plain_text == recovered_plain_text)
    except AssertionError:
        print ("Original plain text is different from decrypted text.")
        raise SystemExit(10)
    else:
        print ("Encryption/decryption cycle test completed successfully!")