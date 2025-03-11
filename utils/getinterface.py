from scapy.arch.windows import get_windows_if_list
from pprint import pprint


interfaces = get_windows_if_list()

pprint(interfaces)