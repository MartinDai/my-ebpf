package util

import (
	"fmt"
	"github.com/MartinDai/my-ebpf/pkg/model"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"path"
	"path/filepath"
	"syscall"
)

func GetConfig(configFile string) (*model.Config, error) {
	var config model.Config
	err := loadConfig(configFile, &config)
	if err != nil {
		return nil, err
	}

	err = checkConfig(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func checkConfig(config *model.Config) error {
	if config.Pid <= 0 {
		config.Pid = 0
		return nil
	}

	err := validatePID(config.Pid)
	if err != nil {
		return fmt.Errorf("pid is not valid")
	}

	return nil
}

func loadConfig(configFile string, config interface{}) error {
	if configFile == "" {
		return fmt.Errorf("config file not specified")
	}

	fileExt := path.Ext(configFile)
	if fileExt != ".yml" && fileExt != ".yaml" {
		return fmt.Errorf("config file only supports .yml or .yaml format")
	}

	absolutePath, err := filepath.Abs(configFile)
	if err != nil {
		return err
	}

	k := koanf.New("::")
	err = k.Load(file.Provider(absolutePath), yaml.Parser())
	if err != nil {
		return err
	}

	err = k.Unmarshal("", config)
	if err != nil {
		return err
	}

	return nil
}

func validatePID(pid int) error {
	err := syscall.Kill(pid, 0)
	if err != nil {
		return err
	}
	return nil
}
