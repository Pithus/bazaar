from re import I, findall
from re import compile as rcompile
from binascii import unhexlify
from ipaddress import ip_address
from copy import deepcopy

class Patterns:
    '''
    QBPatterns for detecting common patterns
    '''
    def __init__(self, data):
        '''
        Initialize QBPatterns, this has to pass
        '''
        self.links = rcompile(r"((?:(smb|srm|ssh|ftps|file|http|https|ftp):\/\/)?[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)+([a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-]*[a-zA-Z0-9_\,\'\/\+&amp;%#\$\?\=~\.\-])?)", I)
        self.ip4 = rcompile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\b', I)
        self.ip4andports = rcompile(r'\b((?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9]):[0-9]{1,5})\b', I)
        self.ip6 = rcompile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', I)
        self.email = rcompile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
        self.tel = rcompile(r'(\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*)', I)
        self.html = rcompile(r'>([^<]*)<\/', I)
        self.hex = rcompile(r'([0-9a-fA-F]{4,})', I)
        self.wordsstripped = str(data)

    def check_link(self, _data):
        '''
        check if buffer contains ips xxx://xxxxxxxxxxxxx.xxx
        '''
        temp_list = []
        temp_var = list(set(findall(self.links, self.wordsstripped)))
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "Link":temp_var})

    def check_ip4(self, _data):
        '''
        check if buffer contains ips x.x.x.x
        '''
        temp_list = []
        temp_var = findall(self.ip4, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                try:
                    ip_address(_)
                    temp_list.append(_)
                except:
                    pass
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "IP":temp_var, "Code":"", "Alpha2":"", "Description":""})

    def check_ip4_ports(self, _data):
        '''
        check if buffer contains ips x.x.x.x:xxxxx
        '''
        temp_list = []
        temp_var = findall(self.ip4andports, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                try:
                    temp_ip, temp_port = _.split(":")
                    ip_address(temp_ip)
                    temp_list.append(_)
                except:
                    pass
        for temp_var in set(temp_list):
            temp_ip, temp_port = temp_var.split(":")
            _data.append({"Count":temp_list.count(temp_var), "IP":temp_ip, "Port":temp_port, "Description":""})

    def check_ip6(self, _data):
        '''
        check if buffer contains ips x.x.x.x
        '''
        temp_list = []
        temp_var = findall(self.ip6, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "IP":temp_var, "Code":"", "Alpha2":"", "Description":""})

    def check_email(self, _data):
        '''
        check if buffer contains email xxxxxxx@xxxxxxx.xxx
        '''
        temp_list = []
        temp_var = findall(self.email, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_[0])
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "EMAIL":temp_var})


    def check_phone_number(self, _data):
        '''
        check if buffer contains tel numbers 012 1234 567
        '''
        temp_list = []
        temp_var = findall(self.tel, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "TEL":temp_var})


    def check_tags(self, _data):
        '''
        check if buffer contains tags <>
        '''
        temp_list = []
        temp_var = findall(self.html, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            _data.append({"Count":temp_list.count(temp_var), "TAG":temp_var})


    def check_hex(self, _data):
        '''
        check if buffer contains tags <>
        '''
        temp_list = []
        temp_var = findall(self.hex, self.wordsstripped)
        if len(temp_var) > 0:
            for _ in temp_var:
                temp_list.append(_)
        for temp_var in set(temp_list):
            try:
                parsed = unhexlify(temp_var)
                _data.append({"Count":temp_list.count(temp_var), "HEX":temp_var, "Parsed":parsed.decode('utf-8', errors="ignore")})
            except:
                pass


    def analyze(self, data=None):
        if not data:
            data = {
                'links': [],
                'ip4s': [],
                'ip4_ports': [],
                'ip6s': [],
                'emails': [],
                'tags': [],
                'hex': [],
            }
        self.check_link(data['links'])
        self.check_ip4(data['ip4s'])
        self.check_ip4_ports(data['ip4_ports'])
        self.check_ip6(data['ip6s'])
        self.check_email(data['emails'])
        self.check_tags(data['tags'])
        self.check_hex(data['hex'])
        return data
