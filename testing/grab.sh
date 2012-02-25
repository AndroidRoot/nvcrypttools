#!/bin/bash
set -x
EXTRA_ARGS="-W -K 00000000000000000000000000000000"

cd $(dirname $0)

adb devices

adb shell "su -c 'rm /data/local/test.blob'"
adb shell "su -c 'rm /data/local/test.ebt'"
adb shell "su -c 'rm /data/local/testc.bct'"
adb shell "su -c 'rm /data/local/testr.bct'"


adb shell "su -c '/data/local/mknvfblob $EXTRA_ARGS --blob /data/local/test.blob --bctin /data/local/test.bct --bctr /data/local/testr.bct --bctc /data/local/testc.bct --blin /data/local/bl-9.4.2.28.ebt  --blout /data/local/test.ebt'"

adb shell "su -c 'chmod 666 /data/local/test.blob'"
adb shell "su -c 'chmod 666 /data/local/test.ebt'"
adb shell "su -c 'chmod 666 /data/local/testr.bct'"
adb shell "su -c 'chmod 666 /data/local/testc.bct'"

adb pull /data/local/test.blob
adb pull /data/local/test.ebt
adb pull /data/local/testc.bct
adb pull /data/local/testr.bct
