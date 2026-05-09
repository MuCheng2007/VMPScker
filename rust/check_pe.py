with open("target/debug/ConsoleApplication1.exe", "rb") as f:
    f.seek(0x561)
    data = f.read(32)
    print("Original file data at file offset 0x561:", data.hex())

with open("target/debug/test_protected.exe", "rb") as f:
    f.seek(0x561)
    data = f.read(32)
    print("Protected file data at file offset 0x561:", data.hex())

    f.seek(0x561 - 5)
    data = f.read(10)
    print("Protected file data around patch_va (0x1161-5):", data.hex())
