import os
import sys
import ctypes

#-----------------------------------------
def randombytes(size):
    return os.urandom(size)

PICNIC_BUILD_DEFAULT_RNG = True
SUPERCOP = False

def random_bytes_default(buf, length):
    if sys.platform.startswith('linux'):
        try:
            with open('/dev/urandom', 'rb') as f:
                buf[:] = f.read(length)
            return 0
        except:
            return -1
    elif sys.platform.startswith('win'):
        try:
            from ctypes import wintypes

            BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
            bcrypt = ctypes.WinDLL('bcrypt.dll')

            NTSTATUS = wintypes.LONG
            PUCHAR = ctypes.POINTER(ctypes.c_ubyte)
            ULONG = wintypes.ULONG

            bcrypt.BCryptGenRandom.restype = NTSTATUS
            bcrypt.BCryptGenRandom.argtypes = [wintypes.LPVOID, PUCHAR, ULONG, ULONG]

            buf_ptr = (ctypes.c_ubyte * length).from_buffer(buf)
            status = bcrypt.BCryptGenRandom(None, buf_ptr, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            if status == 0:
                return 0
            else:
                return -4
        except Exception as e:
            return -1
    else:
        raise NotImplementedError("If neither Linux nor Windows are defined, you'll have to implement the random number generator")

if PICNIC_BUILD_DEFAULT_RNG:
    def get_random_bytes(length):
        buf = bytearray(length)
        ret = random_bytes_default(buf, length)
        if ret != 0:
            raise ValueError(f"Error generating random bytes: {ret}")
        return buf

if SUPERCOP:
    def random_bytes_supercop(buf, length):
        randombytes(buf, length)
        return 0
#-----------------------------------------