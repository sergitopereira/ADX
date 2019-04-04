import re


class ADX(object):
    def __init__(self, running_config):
        self.runconf = running_config.split('\n')

    def virtual_info(self):
        """
        Method to Parse Virtual Server configuration
        :return: Dictionary
        """
        virt_info = {}

        # regular expression to identify ssl-sni profile
        reg4 = r'(ssl-sni)\s(.*)'
        vip_data = []
        look_profile = False
        for item in self.runconf:
            # Regular expression to obtain virtual server name
            virtual_name = re.search(r'server virtual\s+(.*?)\s+', item)
            if virtual_name:
                name = virtual_name.group(1)
                virt_info[name] = []
                look_profile = True
                continue
            if look_profile:
                look_sni = True
                # Regular expression to identify ssl-terminate ssl-proxi
                ssl_terminate = re.search(r'(ssl-terminate)\s(.*?)\s+(.*)', item)
                # regular expression to identify ssl-proxy profile
                ssl_proxy = re.search(r'(ssl-proxy)\s?(.*)', item)
                if ssl_terminate:
                    vip_data.append({'ssl_terminate': ssl_terminate.group(1)})
                    vip_data.append({'ssl_proxy': None})
                    continue
                if ssl_proxy:
                    vip_data.append({'ssl_terminate': None})
                    vip_data.append({'ssl_proxy': ssl_proxy.group(2)})
                    continue
                if look_sni:
                    # regular expresion to identify ssl-sni profile
                    ssl_sni = re.search(r'(ssl-sni)\s(.*)', item)
                    if ssl_sni:
                        vip_data.append({'ssl_sni': ssl_sni.group(1)})
                        continue
                virt_info[name] = vip_data

                if '!' in item:
                    look_profile = False

        return virt_info
