#!/usr/bin/python3
import re
import sys
import socket
import shlex
from subprocess import Popen, PIPE

pattern_line_with_ip = re. \
    compile(r'\s*?(\d{1,2}).*?\s*?\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s*?\d*?\.\d*?\s*?ms\s*?\d*?\.\d*?\s*?ms\s*?\d*?\.\d*?\s*?ms.*?')
pattern_line_with_asterisk = re.compile(r'\s*?(\d{1,2})\s*?\*\s*?\*\s*?\*\s*?(\w*?).*?')
pattern_whois = re.compile(r'(\d*?)?\s*?\|\s*?.*?\|\s*?.*?\|\s*?(\w*?)?\s*?\|\s*?(\w*?)?\s*?\|\s*?.*?\|\s*?.*?')


def tracing(domain_name_or_ip):
    """Main trace function.
    Accepts one argument - domain name or ip address."""
    result = Popen([f'traceroute -I {domain_to_ip(domain_name_or_ip)}'], shell=True, universal_newlines=True,
                   stdout=PIPE)
    count_lines = 0
    count_with_asterisk = 0
    while True:
        if count_with_asterisk > 2:
            sys.exit()
        line = result.stdout.readline()
        if not line:
            if count_lines <= 3:
                print("Нет доступа в интернет. Проверьте подключение к сети.")
            break
        count_lines += 1
        if count_lines == 2:
            row_table("№", "IP", "AS", "Country", "Registry")
        decode_line = line
        matcher = re.findall(pattern_line_with_ip, decode_line)
        if matcher:
            count_with_asterisk = 0
            domain = domain_to_ip(matcher[0][1])
            info = identify_as(domain)
            if info[0] == '':
                info[0] = 'No info'
                info[1] = 'No info'
                row_table(matcher[0][0], matcher[0][1], info[0], info[1], info[2])
            if re.match(pattern_line_with_asterisk, decode_line):
                match_asterisk = re.findall(pattern_line_with_asterisk, decode_line)
                row_table(match_asterisk[0][0], '*', '-', '-', '-')
                count_with_asterisk += 1


def domain_to_ip(domain):
    """Converts the domain name to an ip address."""
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print('Проверьте корректность доменного имени.')
        sys.exit()
    return ip


def row_table(number, ip, autonomous, country, registry):
    """Prints a table row."""
    print('| ' + number + ' ' * (3 - len(number)) + '| ' + ip + ' ' * (15 - len(ip))
          + '| ' + autonomous + ' ' * (15 - len(autonomous)) + '| '
          + country + ' ' * (15 - len(country)) + '| ' + registry + ' ' * (14 - len(registry)) + '|')
    print('-' * 73)


def identify_as(ip):
    """Determines the number of the autonomous system and country of given ip address."""
    whois_as = Popen(shlex.split('whois -h whois.cymru.com — ' + f'\'-v {ip}\''), stdout=PIPE)
    whois_as.stdout.readline()
    info = whois_as.stdout.readline().decode('utf8')
    matcher = re.findall(pattern_whois, info)
    if matcher:
        return [matcher[0][0], matcher[0][1], matcher[0][2]]


def main():
    list_str = ["Scripts accepts one parameter: ",
                "domain/ip for which you need to trace."]
    domain = ''
    if len(sys.argv) == 2:
        domain = sys.argv[1]
    else:
        print(*list_str)

    if not domain:
        sys.exit("Parameter is missing. Scripts accepts one parameter: domain/ip for which you need to trace.")
    try:
        if domain:
            tracing(domain)
    except Exception as e:
        sys.exit(e)


if __name__ == "__main__":
    main()
