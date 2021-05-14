package main

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
)

var (
	homeDir, _ = os.UserHomeDir()
	defaultPaths = []string{
		homeDir + "/.pcap_remote.yml",
		"/etc/pcap_remote.yml",
	}
)

type DeviceDescription struct {
	Address string
}

type DeviceList map[string]DeviceDescription

type Config struct {
	Devices DeviceList
}

func NewConfig() Config {
	return Config{
		Devices: make(DeviceList),
	}
}

func (c *Config) Load() error {
	*c = NewConfig()
	
	for _, path := range defaultPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.WithField("path", path).Error(err)
			continue
		}

		f, err := os.Open(defaultPaths[0])
		if err != nil {
			return err
		}
		defer f.Close()

		b, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		if err := yaml.Unmarshal(b, c); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) Save() error {
	f, err := os.Create(defaultPaths[0])
	if err != nil {
		return err
	}
	defer f.Close()

	bytes, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	_, err = f.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}
