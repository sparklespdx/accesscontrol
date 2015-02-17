#!/usr/bin/python
#
# vim: et ai sw=4

import json
import smtplib
import threading

from RPi import GPIO
import sys
import time
import signal
import syslog


class Config(object):
    def __init__(self):
        self.configs = {}

    def add_config_file(self, filename):
        try:
            with open(filename) as file_handle:
                config = json.load(file_handle)
                self.configs[filename] = config
        except IOError:
            self.configs[filename] = {}

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


class CardReader(object):
    # when scan happens, check for authorization, and fire events if successful
    pass


class Door(object):
    # when associate reader sends event, open
    pass


class Locker(object):
    # when associated reader sends read event, open correct user's locker
    pass


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
        self.debug_mode = False

    def debug(self, message):
        if self.debug_mode:
            print message

    def toggle_debug(self):
        if self.debug_mode:
            logger.debug("Disabling debug messages")
        self.debug_mode ^= True
        if self.debug_mode:
            logger.debug("Enabling debug messages")

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

    def report(self, subject):
        syslog.syslog(subject)
        self.debug(subject)
        if self.config.get("emailserver"):
            # TODO: does send_email need to be a function
            t = threading.Thread(target=self.send_email, args=[subject])
            t.start()


config = Config()
logger = Logger(config)


conf_dir = "./conf/"


def initialize():
    GPIO.setmode(GPIO.BCM)
    syslog.openlog("accesscontrol", syslog.LOG_PID, syslog.LOG_AUTH)
    logger.report("Initializing")
    read_configs()
    setup_output_GPIOs()
    setup_readers()
    # Catch some exit signals
    signal.signal(signal.SIGINT, cleanup)  # Ctrl-C
    signal.signal(signal.SIGTERM, cleanup)  # killall python
    # These signals will reload users
    signal.signal(signal.SIGHUP, rehash)  # killall -HUP python
    signal.signal(signal.SIGUSR2, rehash)  # killall -USR2 python
    # This one will toggle debug messages
    signal.signal(signal.SIGWINCH, toggle_debug)  # killall -WINCH python
    logger.report("%s access control is online" % zone)


def rehash(signal=None, b=None):
    logger.report("Reloading access list")
    config.add_config_file(conf_dir + "users.json")


def read_configs(config):
    config.add_config_file(conf_dir + "users.json")
    config.add_config_file(conf_dir + "config.json")
    config.add_config_file(conf_dir + "locker.json")


def setup_output_GPIOs():
    if (zone == "locker"):
        for number in iter(locker):
            gpio = locker[number]["latch_gpio"]
            zone_by_pin[gpio] = "locker"
            init_GPIO(gpio)
    else:
        zone_by_pin[config[zone]["latch_gpio"]] = zone
        init_GPIO(config[zone]["latch_gpio"])


def init_GPIO(gpio):
    GPIO.setup(gpio, GPIO.OUT)
    lock(gpio)


def lock(gpio):
    GPIO.output(gpio, active(gpio) ^ 1)


def unlock(gpio):
    GPIO.output(gpio, active(gpio))


def active(gpio):
    zone = zone_by_pin[gpio]
    return config[zone]["unlock_value"]


def unlock_briefly(gpio):
    unlock(gpio)
    time.sleep(config[zone]["open_delay"])
    lock(gpio)


def setup_readers():
    global zone_by_pin
    for name in iter(config):
        if name == "<zone>":
            continue
        if (type(config[name]) is dict and config[name].get("d0")
                                       and config[name].get("d1")):
            reader = config[name]
            reader["stream"] = ""
            reader["timer"] = None
            reader["name"] = name
            reader["unlocked"] = False
            zone_by_pin[reader["d0"]] = name
            zone_by_pin[reader["d1"]] = name
            GPIO.setup(reader["d0"], GPIO.IN)
            GPIO.setup(reader["d1"], GPIO.IN)
            GPIO.add_event_detect(reader["d0"], GPIO.FALLING,
                                  callback=data_pulse)
            GPIO.add_event_detect(reader["d1"], GPIO.FALLING,
                                  callback=data_pulse)


def data_pulse(channel):
    reader = config[zone_by_pin[channel]]
    if channel == reader["d0"]:
        reader["stream"] += "0"
    elif channel == reader["d1"]:
        reader["stream"] += "1"
    kick_timer(reader)


def kick_timer(reader):
    if reader["timer"] is None:
        reader["timer"] = threading.Timer(0.2, wiegand_stream_done,
                                          args=[reader])
        reader["timer"].start()


def wiegand_stream_done(reader):
    if reader["stream"] == "":
        return
    bitstring = reader["stream"]
    reader["stream"] = ""
    reader["timer"] = None
    validate_bits(bitstring)


def validate_bits(bstr):
    if len(bstr) != 26:
        logger.debug("Incorrect string length received: %i" % len(bstr))
        logger.debug(":%s:" % bstr)
        return False
    lparity = int(bstr[0])
    facility = int(bstr[1:9], 2)
    user_id = int(bstr[9:25], 2)
    rparity = int(bstr[25])
    logger.debug("%s is: %i %i %i %i" % (bstr, lparity, facility, user_id, rparity))

    calculated_lparity = 0
    calculated_rparity = 1
    for iter in range(0, 12):
        calculated_lparity ^= int(bstr[iter + 1])
        calculated_rparity ^= int(bstr[iter + 13])
    if (calculated_lparity != lparity or calculated_rparity != rparity):
        logger.debug("Parity error in received string!")
        return False

    card_id = "%08x" % int(bstr, 2)
    logger.debug("Successfully decoded %s facility=%i user=%i" %
          (card_id, facility, user_id))
    lookup_card(card_id, str(facility), str(user_id))


def lookup_card(card_id, facility, user_id):
    user = (users.get("%s,%s" % (facility, user_id)) or
            users.get(card_id) or
            users.get(card_id.upper()) or
            users.get(user_id))
    if (user is None):
        logger.debug("couldn't find user")
        return reject_card()
    if (zone == "locker" and user.get("locker")):
        open_locker(user)
    elif (user.get(zone) and user[zone] == "authorized"):
        open_door(user)
    else:
        logger.debug("user isn't authorized for this zone")
        reject_card()


def reject_card():
    logger.report("A card was presented at %s and access was denied" % zone)
    return False


def open_locker(user):
    userlocker = user["locker"]
    if locker.get(userlocker) is None:
        return logger.debug("%s's locker does not exist" % user["name"])
    if (locker[userlocker]["zone"] == lockerzone):
        logger.report("%s has opened their locker" % public_name(user))
        unlock_briefly(locker[userlocker]["latch_gpio"])


def public_name(user):
    first, last = user["name"].split(" ")
    return "%s %s." % (first, last[0])


def open_door(user):
    global open_hours, last_name, repeat_read_timeout, repeat_read_count
    now = time.time()
    name = public_name(user)
    if (name == last_name and now <= repeat_read_timeout):
        repeat_read_count += 1
    else:
        repeat_read_count = 0
        repeat_read_timeout = now + 30
    last_name = name
    if (repeat_read_count >= 2):
        config[zone]["unlocked"] ^= True
        if config[zone]["unlocked"]:
            unlock(config[zone]["latch_gpio"])
            logger.report("%s unlocked by %s" % (zone, name))
        else:
            lock(config[zone]["latch_gpio"])
            logger.report("%s locked by %s" % (zone, name))
    else:
        if config[zone]["unlocked"]:
            logger.report("%s found %s is already unlocked" % (name, zone))
        else:
            unlock_briefly(config[zone]["latch_gpio"])
            logger.report("%s has entered %s" % (name, zone))


def cleanup(a=None, b=None):
    message = ""
    if zone:
        message = "%s " % zone
    message += "access control is going offline"
    logger.report(message)
    GPIO.setwarnings(False)
    GPIO.cleanup()
    sys.exit(0)

zone_by_pin = {}
repeat_read_count = 0
repeat_read_timeout = time.time()


if __file__ == '__main__':
    initialize()
    while True:
        # The main thread should open a command socket or something
        time.sleep(1000)
