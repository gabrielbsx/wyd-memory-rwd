import ctypes
from ReadWriteMemory import ReadWriteMemory

if __name__ == '__main__':
    process = ReadWriteMemory().get_process_by_name('notepad.exe')
    process.open()
    print(process.get_pointer(0x61AAAB8))
    pass