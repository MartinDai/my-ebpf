package util

import (
	"os"
	"path/filepath"
)

func SaveFile(filePath string, data []byte) error {
	var err error
	if err = createDirectories(filepath.Dir(filePath)); err != nil {
		return err
	}

	var file *os.File
	if file, err = os.Create(filePath); err != nil {
		return err
	}
	defer file.Close() // 确保在函数退出前关闭文件

	// 2. 将数据写入文件
	if _, err = file.Write(data); err != nil {
		return err
	}

	return nil
}

func createDirectories(dirPath string) error {
	// 使用os.MkdirAll创建包含目录结构的目录
	if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {
		return err
	}
	return nil
}
