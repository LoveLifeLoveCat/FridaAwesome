import frida,sys


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


jscode = """
Java.perform(function () {});
"""

process = frida.get_usb_device().spawn('com.miduoki.awesome')
script = process.create_script(jscode)
# script.on('message', on_message)
# print('[*] Running CTF')
# script.load()
# sys.stdin.read()

# frida-ps -U
# com.miduoki.awesome
