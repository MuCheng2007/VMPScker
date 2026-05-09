import os

def rename_rs_to_txt():
    """
    将当前目录下所有.rs文件重命名为.txt文件
    """
    # 获取当前目录
    current_dir = os.getcwd()
    
    # 遍历当前目录下的所有文件
    for filename in os.listdir(current_dir):
        # 检查文件是否以.rs结尾
        if filename.endswith('.rs'):
            # 构建新的文件名
            new_filename = filename[:-3] + '.txt'
            
            # 获取完整的文件路径
            old_path = os.path.join(current_dir, filename)
            new_path = os.path.join(current_dir, new_filename)
            
            try:
                # 重命名文件
                os.rename(old_path, new_path)
                print(f"已重命名: {filename} -> {new_filename}")
            except Exception as e:
                print(f"重命名失败 {filename}: {e}")

if __name__ == "__main__":
    rename_rs_to_txt()
