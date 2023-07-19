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
	var err error
	if err = loadConfig(configFile, &config); err != nil {
		return nil, err
	}

	if err = checkConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func checkConfig(config *model.Config) error {
	if config.Pid <= 0 {
		config.Pid = 0
		return nil
	}

	if err := validatePID(config.Pid); err != nil {
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

	var absolutePath string
	var err error
	if absolutePath, err = filepath.Abs(configFile); err != nil {
		return err
	}

	k := koanf.New("::")
	if err = k.Load(file.Provider(absolutePath), yaml.Parser()); err != nil {
		return err
	}

	if err = k.Unmarshal("", config); err != nil {
		return err
	}

	return nil
}

func validatePID(pid int) error {
	if err := syscall.Kill(pid, 0); err != nil {
		return err
	}
	return nil
}
