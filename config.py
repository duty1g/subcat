import yaml
import os


class Config:
    def __init__(self, logger=None, config: str = 'config.yaml'):
        self.logger = logger
        # Check if config is an absolute path; if not, use current file's directory.
        if not os.path.isabs(config):
            dir_path = os.path.dirname(os.path.realpath(__file__))
            self.config = os.path.join(dir_path, config)
        else:
            self.config = config

        # Check if the file exists
        if not os.path.exists(self.config):
            if self.logger:
                self.logger.error(f"Config file not found: {self.config}")
            else:
                print(f"Config file not found: {self.config}")
            self.config = None

    def read(self, module: str):
        if not self.config:
            return False
        try:
            with open(self.config, 'r') as f:
                data = yaml.safe_load(f)
            # Return the module data if present, else False
            return data.get(module, False)
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to read config file: {e}")
            else:
                print(f"Failed to read config file: {e}")
            return False
