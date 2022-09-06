import argparse
import inspect
import sys
import threading
import time

from honey_log.server.logging_server import LoggingServer
from honey_os.process import Process


def print_banner():
    banner_file = open("banner.txt")
    lines = banner_file.readlines()
    for line in lines:
        print(line, end='')
    print()
    banner_file.close()


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='Submodule logging client.')
        parser.add_argument('--ip', help='Server IP')
        parser.add_argument('--port', help='Server port')
        parser.add_argument('--server-only', help='Launch server without submodules', action='store_true')
        parser.add_argument('--no-smb', help="Don't launch SMB submodule", action='store_true')
        parser.add_argument('--no-http', help="Don't launch HTTP submodule", action='store_true')
        parser.add_argument('--no-nmap', help="Don't launch NMap submodule", action='store_true')
        parser.add_argument('--no-ssh', help="Don't launch SSH submodule", action='store_true')
        parser.add_argument('--no-reporting', help="Only log locally, don't report to web backend", action='store_true')
        args = parser.parse_args()
        if args.ip is not None:
            host = args.ip
        else:
            host = None
        if args.port is not None:
            port = args.port
        else:
            port = None

        print_banner()

        # Start server and wait a bit to start clients.
        logging_server = LoggingServer(args.no_reporting, host, port)
        threading.Thread(target=logging_server.listen, args=()).start()
        time.sleep(1)
        cwd = '/'.join(sys.argv[0].split('/')[:-1])
        if not args.server_only:
            if not args.no_smb:
                # Start SMB Server
                smb_thread = threading.Thread(target=Process.call, args=((cwd + '/honey_smb/HoneySMB2/launch.sh'),))
                smb_thread.daemon = True
                smb_thread.start()

            if not args.no_ssh:
                # Start SSH Server
                ssh_thread = threading.Thread(target=Process.call, args=((cwd + '/honey_ssh/launch.sh'),))
                ssh_thread.daemon = True
                ssh_thread.start()

            if not args.no_http:
                # Start HTTP Server
                http_thread = threading.Thread(target=Process.call, args=((cwd + '/honey_http/launch.sh'),))
                http_thread.daemon = True
                http_thread.start()

            if not args.no_nmap:
                # Import down here so logging server doesn't refuse client connection.
                from honey_os.os_obfuscation import OSObfuscation
                import honey_os.template.os_templates.template_list

                # Start NMap Server
                nmap_thread = threading.Thread(OSObfuscation.run(
                    template_path="/".join(
                        inspect.getabsfile(inspect.currentframe()).split("/")[:-1]) + "/honey_os/template/os_templates/" +
                                  honey_os.template.os_templates.template_list.template_list[
                                      honey_os.template.os_templates.template_list.use_template], server_ip="127.0.0.1"))
                nmap_thread.daemon = True
                nmap_thread.start()
    except Exception as e:
        import traceback
        traceback.print_exc()
    finally:
        print("Logging server closing down...")
