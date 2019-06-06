#!/usr/bin/python
#
# vim: et ai sw=4

import json
import smtplib
import threading

from RPi import GPIO
from smbus import SMBus
import sys
import time
import signal
import syslog
import socket

conf_dir = "./conf/"


class Config(object):

    def __init__(self):
        self.configs = {"i2c":{}}

    def add_config_file(self, filename):
        try:
            with open(conf_dir + filename + ".json") as file_handle:
                try:
                    config = json.load(file_handle)
                    if config > 0:
                        self.configs[filename] = config
                except ValueError:
                    logger.report("%s unable to load %s file.  Please check for syntax errors." %
                                (socket.gethostname(), filename))
        except IOError:
            self.configs[filename] = {} # FIXME figure out how to revert on a bad read

    def __getitem__(self, item):
        for config in self.configs.values():
            val = config.get(item)
            if val is not None:
                return val
        return None

    def __getattr__(self, item):
        if item in self.configs:
            return self.configs[item]
        raise AttributeError()


class Output(object):
    # GPIOs and I2C shift-register outputs

    def __init__(self, address, unlock_value, open_delay):
        if type(address) is int:
            GPIO.setup(address, GPIO.OUT)
        self.address = address
        self.unlock_value = unlock_value
        self.open_delay = open_delay
        self.deactivate()

    def set_out(self, go_active=False):
        new_value = go_active ^ self.unlock_value ^ 1
        if type(self.address) is int:
            GPIO.output(self.address, new_value)
        elif type(self.address) is unicode:
            (addr, bit) = [int(x, 16) for x in self.address.split('.')]
            if not config.i2c.get(addr):
                config.i2c[addr] = 0
            if new_value:
                config.i2c[addr] |= 1 << bit
            else:
                config.i2c[addr] &= 1 << bit ^ 0xFF
            bus.write_byte_data(addr, 0x44, config.i2c[addr])   # TPIC2810 compatible
        else:
            debug("gpio is unknown type: %s" % type(self.address))

    def deactivate(self):
        self.set_out(False)

    def activate(self):
        self.set_out(True)

    def timed_activation(self):
        self.activate()
        time.sleep(self.open_delay)
        self.deactivate()


class CardReader(object):
    # when scan happens, validate, check for authorization, and fire events if successful

    def __init__(self, reader_config):
        if reader_config["name"] == "<door_name>":
            return None
        if reader_config["is_locker"]:
            self.is_locker = True
            self.lockers = []
            for locker in reader_config["doors"]:
                self.lockers.append(Locker(locker, self))
        else:
            self.is_locker = False
            self.door = Door(reader_config["doors"][0], self)
        if reader_config.get("led"):
            self.led = Output(reader_config["led"], 1, 1)
        self.name = reader_config["name"]
        self.stream = ""
        self.timer = None
        self.unlocked = False
        self.data0 = reader_config["data0"]
        self.data1 = reader_config["data1"]
        self.permissions = reader_config["permissions"]
        self.permissions.append(self.name)
        GPIO.setup(self.data0, GPIO.IN)
        GPIO.setup(self.data1, GPIO.IN)
        GPIO.add_event_detect(self.data0, GPIO.FALLING,
                              callback=self.data_pulse)
        GPIO.add_event_detect(self.data1, GPIO.FALLING,
                              callback=self.data_pulse)

    def find_locker(self, name):
        for locker in self.lockers:
            if locker.name == name:
                return locker
        return None

    def data_pulse(self, channel):
        if channel == self.data0:
            self.stream += "0"
        elif channel == self.data1:
            self.stream += "1"
        self.kick_timer()

    def kick_timer(self):
        if self.timer is None:
            self.timer = threading.Timer(0.2, self.wiegand_stream_done)
            self.timer.start()

    def wiegand_stream_done(self):
        if self.stream == "":
            return
        bstr = self.stream
        self.stream = ""
        self.timer = None

        # verify length and split into components
        if len(bstr) != 26:
            logger.debug("%s received bad string length: %i\n:%s:" %
                    (self.name, len(bstr), bstr))
            return False
        lparity = int(bstr[0])
        facility = str(int(bstr[1:9], 2))
        user_id = str(int(bstr[9:25], 2))
        rparity = int(bstr[25])
        logger.debug("%s %s is: %i %s %s %i" %
                (self.name, bstr, lparity, facility, user_id, rparity))

        # verify parity
        calculated_lparity = 0
        calculated_rparity = 1
        for iter in range(0, 12):
            calculated_lparity ^= int(bstr[iter + 1])
            calculated_rparity ^= int(bstr[iter + 13])
        if (calculated_lparity != lparity or calculated_rparity != rparity):
            logger.debug("%s received string with bad parity!" % self.name)
            return False

        card_id = "%08x" % int(bstr, 2)
        logger.debug("%s successfully decoded %s facility=%s user=%s" %
              (self.name, card_id, facility, user_id))

        # lookup card
        user = (config.users.get("%s,%s" % (facility, user_id)) or
                config.users.get(card_id) or
                config.users.get(card_id.upper()) or
                config.users.get(user_id))
        if (user is None):
            logger.debug("couldn't find user")
            return self.reject_card()
        if (self.is_locker and user.get("locker")):
            found_locker = self.find_locker(user["locker"])
            if found_locker is None:
                return logger.debug("%s does not have a locker" % user["name"])
            return found_locker.open_locker(user)
        else:
            # normal user auth
            for my_permission in self.permissions:
                if my_permission == "*" or my_permission in user["permissions"]:
                    return self.door.open_door(user)
            # event mode unlock
            if "event mode" in user["permissions"]:
                if self.door.last_opened > time.time() - 10 or self.door.unlocked:
                    return self.door.toggle_lock(user)
        logger.debug("%s is not authorized for %s" %
                (user["name"], self.name))
        self.reject_card()

    def reject_card(self):
        logger.report("A card was presented at %s %s and access was denied" %
                    (socket.gethostname(), self.name))
        return False


class Door(object):
    # when associate reader sends event, open

    def __init__(self, door_config, reader):
        self.reader = reader
        self.name = door_config["name"]
        self.latch = Output(door_config["latch_gpio"], door_config["unlock_value"], door_config["open_delay"])
        self.open_delay = door_config["open_delay"]
        self.unlocked = False
        self.last_opened = None

    def toggle_lock(self, user):
        public_name = logger.public_name(user)
        self.unlocked ^= True
        if self.unlocked:
            logger.report("%s %s locked by %s" % (socket.gethostname(), self.name, public_name))
            self.latch.activate()
            self.reader.led.activate()
        else:
            logger.report("%s %s unlocked by %s" % (socket.gethostname(), self.name, public_name))
            self.latch.deactivate()
            self.reader.led.deactivate()

    def open_door(self, user):
        now = time.time()
        public_name = logger.public_name(user)
        if self.unlocked:
            logger.report("%s found %s %s is already unlocked" %
                        (public_name, socket.gethostname(), self.name))
        else:
            logger.report("%s has opened %s %s" %
                        (public_name, socket.gethostname(), self.name))
            self.last_opened = now
            self.latch.activate()
            time.sleep(self.open_delay)
            if not self.unlocked:
                self.latch.deactivate()

class Locker(object):
    # when associated reader sends read event, open correct user's locker

    def __init__(self, locker_config, reader):
        self.name = locker_config["name"]
        self.reader = reader
        self.latch = Output(locker_config["latch_gpio"], locker_config["unlock_value"], locker_config["open_delay"])
        #self.unlocked = False

    def open_locker(self, user):
        logger.report("%s has opened %s locker %s" %
                (logger.public_name(user), socket.gethostname(), self.name))
        self.latch.timed_activation()


class AdvancedRule(object):
    # can subscribe to any events (signals, card reads, successful card authorizations,
    # time(?), door open/close.
    # has access to all system information
    # can alter the structure of readers, doors, configs, rules.
    # maybe we just initialize these with a global function and let it do whatever...
    pass


class Logger(object):

    def __init__(self, config):
        self.config = config
        self.debug_mode = True

    def debug(self, message):
        if self.debug_mode:
            print message
            sys.stdout.flush()

    def toggle_debug(self, sig, frame):
        if self.debug_mode:
            self.debug("Disabling debug messages")
        self.debug_mode ^= True
        if self.debug_mode:
            self.debug("Enabling debug messages")

    def send_email(self, subject, body=""):
        try:
            emailfrom = self.config["emailfrom"]
            to = self.config["emailto"]
            smtpserver = smtplib.SMTP(self.config["emailserver"], self.config["emailport"])
            smtpserver.ehlo()
            header = "To: %s\nFrom: %s\nSubject: %s\n" % (to, emailfrom, subject)
            msg = "%s\n%s\n\n" % (header, body)
            smtpserver.sendmail(emailfrom, to, msg)
            smtpserver.close()
        except smtplib.SMTPException:
            # couldn't send.
            pass

    def public_name(self, user):
        first, last = user["name"].split(" ")
        return "%s %s." % (first, last[0])

    def report(self, subject):
        syslog.syslog(subject)
        self.debug(subject)
        if self.config["emailserver"]:
            # TODO: does send_email need to be a function
            t = threading.Thread(target=self.send_email, args=[subject])
            t.start()


def initialize(config, logger):
    GPIO.setmode(GPIO.BCM)
    syslog.openlog("accesscontrol", syslog.LOG_PID, syslog.LOG_AUTH)
    logger.report("Initializing")
    config.add_config_file("config")
    config.add_config_file("users")
    setup_readers()
    # Catch some exit signals
    signal.signal(signal.SIGINT, cleanup)   # Ctrl-C
    signal.signal(signal.SIGTERM, cleanup)  # killall python
    # These signals will reload users
    signal.signal(signal.SIGHUP, rehash)    # killall -HUP python
    signal.signal(signal.SIGUSR2, rehash)   # killall -USR2 python
    # This one will toggle debug messages
    signal.signal(signal.SIGWINCH, logger.toggle_debug)  # killall -WINCH python
    logger.report("%s access control is online" % socket.gethostname())

def rehash(signal=None, b=None):
    logger.report("%s reloading access list" % socket.gethostname())
    config.add_config_file("users")

def setup_readers():
    for reader in iter(config["readers"]):
        CardReader(reader)

def cleanup(a=None, b=None):
    logger.report("%s access control is going offline" % socket.gethostname())
    GPIO.setwarnings(False)
    GPIO.cleanup()
    sys.exit(0)


config = Config()
logger = Logger(config)
bus = SMBus(1)

if __name__ == '__main__':
    initialize(config, logger)

    while True:
        # The main thread should open a command socket or something
        time.sleep(1000)
