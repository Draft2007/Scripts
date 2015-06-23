# Copyright (C) 2010-2014 Immunity Inc.
# This file is part of El Jefe - http://www.immunityinc.com/products-eljefe.shtml
# See the file 'docs/LICENSE' for copying permission.


class conf_parser():

    def __init__(self, comment_char = '#', option_char = '=', allow_duplicates = False, strip_quotes = True):
        self.comment_char = comment_char
        self.option_char = option_char
        self.allow_duplicates = allow_duplicates
        self.strip_quotes = True
    
    def parse_config(self, filename):
        self.options = {}
        config_file = open(filename)
        for line in config_file:
            if self.comment_char in line:
                line, comment = line.split(self.comment_char, 1)
            if self.option_char in line:
                option, value = line.split(self.option_char, 1)
                option = option.strip()
                value = value.strip()
                value = value.strip('"\'')
                if self.allow_duplicates:
                    if option in self.options:
                        if not type(self.options[option]) == list:
                            old_value = self.options[option]
                            self.options[option] = [value] + [old_value]
                        else:
                                self.options[option] += [value]
                    else:
                        self.options[option] = value
                else:
                    self.options[option] = value
        config_file.close()
        return self.options
   
    def parse(self,filename):
        return self.parse_config(filename)
    
    def get(self,field):
        return self.options[field]
