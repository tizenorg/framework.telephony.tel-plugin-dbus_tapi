#!/bin/sh

dbus-send --print-reply --reply-timeout=60000 --dest=org.tizen.telephony /org/tizen/telephony/SAMSUNG org.tizen.telephony.Network.Search
