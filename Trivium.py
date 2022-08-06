#Bùi Minh Dũng 20205070
from collections import deque
from itertools import repeat
from sys import version_info
import binascii

class Trivium:
    def __init__(self, key, iv):
        #Bước khởi tạo này ta phải khởi tạo để đưa key và IV vao thanh ghi A,B, state ở đây là một hàng đợi, và ta cho thanh ghi A,B,C vào hàng đợi state này
        
        self.state = None
        self.counter = 0
        self.key = key  
        self.iv = iv  
        #Khởi tạo thanh ghi A với Key
        init_list = list(map(int, list(self.key)))
        init_list += list(repeat(0, 13))
        #Khởi tạo thanh ghi B với IV
        init_list += list(map(int, list(self.iv)))
        init_list += list(repeat(0, 4))
        #Khởi tạo thanh ghi C
        init_list += list(repeat(0, 108))
        init_list += list([1, 1, 1])
        
        self.state = deque(init_list)
        
        #Dùng để bỏ qua 1152 bit đầu tiên (4 vòng đầu) để sinh ra khóa có ích nhất
        for i in range(4*288):
            self._gen_keystream()

    def _gen_keystream(self):
        #Hàm này dùng để khởi tạo mã dòng Trivium, được code theo đặc tả của Trivium
        #Do trong code index bắt đầu từ 0 nên tất cả con số trong lý thuyết đều trừ đi 1
        #Nên thanh ghi A sẽ có vị trí trong queues State là 0-92(93 ô bit), thanh ghi B là 93 - 176 (84 bit) và thanh ghi C là 177 - 287(111 bit)
        
        t_1 = self.state[65] ^ self.state[92]#Khi bit thứ 93 của thanh ghi A đi ra và XOR với bit thứ 66 của thanh ghi A
        t_2 = self.state[161] ^ self.state[176]#Khi bit thứ 84 của thanh ghi B đi ra và XOR với bit thứ 69 của thanh ghi B
        t_3 = self.state[242] ^ self.state[287]#Khi bit thứ 111 của thanh ghi C đi ra và XOR với bit thứ 66 của thanh ghi C

        z = t_1 ^ t_2 ^ t_3#Các bit vừa đi ra sẽ tạo thành bit được XOR lẫn nhau tạo ra mã dòng z

        #Theo sơ đồ các bit từ thanh A,B,C đi ra sẽ có 1 đường đi để ghi vào các Thanh ghi A,B,C
        t_1 = t_1 ^ self.state[90] & self.state[91] ^ self.state[170]#Bit t1 từ thanh ghi A vừa ra, sẽ được XOR với bit sinh ra từ phép toán AND giữa bit 91 và 92 của thanh A, sau đó XOR tiếp với bit 78 của thanh ghi B
        t_2 = t_2 ^ self.state[174] & self.state[175] ^ self.state[263]#Bit t2 từ thanh ghi B vừa ra, sẽ được XOR với bit sinh ra từ phép toán AND giữa bit 82 và 83 của thanh B, sau đó XOR tiếp với bit 87 của thanh ghi C
        t_3 = t_3 ^ self.state[285] & self.state[286] ^ self.state[68]#Bit t3 từ thanh ghi C vừa ra, sẽ được XOR với bit sinh ra từ phép toán AND giữa bit 109 và 110 của thanh C, sau đó XOR tiếp với bit 69 của thanh ghi A

        #Hàm rotate dùng với hàng đợi trong Python sẽ khiến phần tử cuôi trở thành phần từ đầu tiên, các phần từ khác sẽ có vị trí +1 đơn vị
        '''Ví dụ:
        a = deque([1,2,3])
        a.rotate()
        Output: a = deque([3,1,2])
        '''
        self.state.rotate()

        #Bước ghi các bit t1, t2, t3 vừa tạo ra ở trên vào các bit đầu tiên của mỗi thanh ghi
        self.state[0] = t_3#Đi ra từ thanh C, ghi vào A
        self.state[93] = t_1#Đi ra từ thanh A, ghi vào B
        self.state[177] = t_2#Đi ra từ thanh B, ghi vào C

        return z
  
    def keystream(self):
        while self.counter < 2**64:
            self.counter += 1
            yield self._gen_keystream()
    
#Tạo 1 từ điển (Dữ liệu dictionary) để chuyển đổi từ thập phân sang Hexa của 256 số từ 0 đến 255
_allbytes = dict([("%02X" % i, i) for i in range(256)])

#Chuyển 1 chuỗi s dạng hexa sang vị trí thập phân trong bảng ASCII 
def _hex_to_bytes(s):
    return [_allbytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]

#Chuyển từ hexa sang bit(Dùng hàm _hex_to_bytes)
def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s)
            for i in range(8)]

#Chuyển từ bit sang hexa
def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)])
                    for i in range(0, len(b), 8)])

def strxor(a, b):    
    return "".join([str(hex(x ^ y)) for x, y in zip(a, b)])



KEY = hex_to_bits("1A72B50954AE0232A9FA")[::-1]
IV = hex_to_bits("943DF75DC32B12F367D7")[::-1]
trivium = Trivium(KEY, IV)
 # Check python version
if version_info[0] == 2:
    next_key_bit = trivium.keystream().next
elif version_info[0] == 3:
    next_key_bit = trivium.keystream().__next__
else:
    print("invalid python version")
    exit()
#Nhập liệu
stt = input("Hãy nhập thông điệp cần mã hóa: ")
st = stt.encode('ascii')
#Sinh khóa theo độ dài thông điệp (Đã bỏ qua 1152 bit đầu trong phương thức init)
for i in range(1):
    keystream = []
    for j in range(len(stt)*8):
        keystream.append(next_key_bit())
key = binascii.unhexlify(''.join(bits_to_hex(keystream)))
#Chuyển đổi dữ liệu sang nhị phân
string = str(binascii.hexlify(st),'ascii')
for i in range(1):
    stringstream = []
    for j in range(len(stt)*8):
        stringstream.append(next_key_bit())
stringst = binascii.unhexlify(''.join(bits_to_hex(stringstream)))
#XOR và in ra kết quả
xorst = strxor(key,stringst)
print(f"Bản mã ở dạng hexa đã được mã hóa bằng Trivium là: {(''.join(xorst.split('0x'))).upper()}")

