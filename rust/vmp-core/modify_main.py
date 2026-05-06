import sys

file_path = r'E:\Test_C++\ConsoleApplication1\examples\VMProtect_SDK_Example.cpp'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# remove markers from main
old_main_begin = 'VMProtectBeginVirtualization("main");'
old_main_end = 'VMProtectEnd(); // main 保护区结束'

content = content.replace(old_main_begin, '// removed main begin')
content = content.replace(old_main_end, '// removed main end')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
