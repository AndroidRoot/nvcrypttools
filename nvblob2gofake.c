#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include <ezfb.h>
#include <linux/input.h>
#include <linux/loop.h>

#include "mknvfblob.h"
#include "nvaes.h"
#include "nvrcm.h"
#include "device_data.h"
#include "scrollback.h"
#include "gpiokeys.h"

// Use paths without prefix so we can use -I to decide target
#include "device.h"


// Generic defines applicable to all devices.
// Device-specific defines are in device.h
#define DESTBLOB "blob.bin"
#define DESTEBT "bootloader.ebt"
#define DESTBCTR "recovery.bct"
#define DESTBCTC "create.bct"
#define DESTLOG "blob.log"

#define TMP_MOUNT_PATH "/mnt"
#define SYSFS_ANDROID_GADGET "/sys/class/android_usb/android0/"
#define SYSFS_UMS_LUN SYSFS_ANDROID_GADGET "f_mass_storage/lun/"
#define LOOP_FILE "/vfat.img"
#define BLOB_VERSION "v1.5.00000"

#define CHECK_

struct ezfb  fb = {0};

static int loop_fd;

#define MAX_PATH_SIZE 128

void append_log(char *format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end (args);
    printf("LOG: %s\n", buffer);
    fflush(stdout);
    scrollback_putline(buffer);
    ezfb_put_rectangle(&fb, fb.mid_x-349, fb.mid_y-249, fb.mid_x+349, fb.mid_y+249, fb.colors.black, 1);
    scrollback_refresh(&fb);
}


static uint32_t get_chip_type()
{
    char buf[512] = {0};
    char *hardware = NULL;
    FILE *fd;

    if(!(fd = fopen("/proc/cpuinfo", "r"))) {
        perror("failed to retrieve cpu info");
        return CHIP_TYPE_UNKNOWN;
    }

    while((fgets(buf, sizeof(buf), fd)) != NULL) {
        hardware = strtok(buf, ":");

        if(!strncmp(hardware, "Hardware", 8)) {
            hardware = strtok(NULL, ":");
            break;
        }
    }

    fclose(fd);

    if(!hardware)
        return CHIP_TYPE_UNKNOWN;

    while(*hardware == ' ')
        hardware++;

        if(!strncmp(hardware, device_data.name, strlen(device_data.name))) {
            return device_data.type;
    }

    return CHIP_TYPE_UNKNOWN;
}

static void init()
{
    dev_t dev1, dev2;

    /* Basic filesystem initialisation. */
    mkdir("/dev", 0755);
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/data", 0755);
    mkdir("/mnt", 0755);

    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);

#ifndef USE_DEVTMPFS
    mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
    /* Create the only two device nodes we require. */
    dev1 = makedev(DATAMAJOR, DATAMINOR);
    dev2 = makedev(CRYPTOMAJOR, CRYPTOMINOR);
    mknod(DATADEV, 0755 | S_IFBLK, dev1);
    mknod(NVAES_TEGRA_DEVICE, 0755 | S_IFCHR, dev2);
#else
    mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
#endif
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
}


void prepare_loopfs()
{
    int file_fd;
    struct loop_info64 li;
    memset(&li, 0, sizeof(struct loop_info64));

    append_log("Preparing loopback filesystem for blob storage");
    if((file_fd = open(LOOP_FILE, O_RDWR)) < 0)
        append_log("Error opening vfat loop: %s", strerror(errno));
    loop_fd = open("/dev/loop0", O_RDWR);
    ioctl(loop_fd, LOOP_SET_FD, file_fd);
    close(file_fd);
    strncpy((char*)li.lo_file_name, "nvflashtmp", LO_NAME_SIZE);
    ioctl(loop_fd, LOOP_SET_STATUS64, (char *)&li);
//    close(loop_fd);
    if(mount("/dev/loop0", TMP_MOUNT_PATH, "vfat", MS_SYNCHRONOUS, NULL))
    {
        append_log("Error mounting: %s", strerror(errno));
    }
    append_log("Loopback filesystem ready");
}

void disable_loopfs()
{
    append_log("Disabling loopback filesystem");
    umount(TMP_MOUNT_PATH);
    ioctl(loop_fd, LOOP_CLR_FD, 0);
    close(loop_fd);
    loop_fd = -1;
}


void write_sysfs(const char *path, char* value)
{
    FILE * sysfs_file = fopen(path, "w");
    fprintf(sysfs_file, value);
    fclose(sysfs_file);
}

void enable_usbfs()
{
    append_log("Enabling USB Mass Storage mode");

    // Setup names etc, fluff!
    write_sysfs(SYSFS_ANDROID_GADGET "iProduct", "Nvflash" DEVICE_NAME);
    write_sysfs(SYSFS_ANDROID_GADGET "iManufacturer", "AndroidRoot");
    write_sysfs(SYSFS_ANDROID_GADGET "idProduct", "4242");
    write_sysfs(SYSFS_ANDROID_GADGET "idVendor", "0b05");

    // Setup lun
    write_sysfs(SYSFS_UMS_LUN "ro", "1");
    write_sysfs(SYSFS_UMS_LUN "file", LOOP_FILE);
    write_sysfs(SYSFS_ANDROID_GADGET "functions", "mass_storage");
    write_sysfs(SYSFS_ANDROID_GADGET "enable", "1");
}

void disable_usbfs()
{
    append_log("Disable USB Mass Storage mode");
    write_sysfs(SYSFS_ANDROID_GADGET "enable", "0");
}


void refresh_default()
{
    EZFB_FUNCTION_CALL
//    ezfb_clear_screen(&fb);
    ezfb_put_string(&fb,"Nvflash Preparation tool!", fb.mid_x - 225, 60, fb.colors.black, fb.colors.white, 0, 2);
    ezfb_put_string(&fb,"Brought to you by AndroidRoot.Mobi", fb.mid_x - 250, fb.max_y - 60, fb.colors.black, fb.colors.white, 0, 2);
    ezfb_put_string(&fb, "Device: " DEVICE_NAME, 10, fb.max_y-10, ezfb_make_rgb_32bit(&fb, 255,0,0), fb.colors.black, 0, 1);
    ezfb_put_rectangle(&fb, fb.mid_x-350, fb.mid_y-250, fb.mid_x+350, fb.mid_y+250, fb.colors.white, 0);
    EZFB_FUNCTION_RETURN_VOID
}

int main(int argc, char * const *argv)
{
    char *buf, iv[AES_BLOCK_SIZE] = {0};
    int bctc = 0, bctr = 0, blout = 0, blob = 0, log = 0;
    uint32_t chip = 0;
    static struct chip_data *chipdata;
    nvaes_ctx ctx;
    int i,j,k;

    EZFB_FUNCTION_CALL_0
    if(!strncmp(argv[0], "/init", 5)) {
        init();

// TODO: Attempt this once files are ready on loopback fs
/*        if(mount(DATADEV, DATADIR, DATAFS, MS_SYNCHRONOUS, "")) {
            perror("failed to mount data partition");
            goto fail;
        }*/
    }

    if(!ezfb_init(&fb, EZFB_SAVE_SCREEN)) {
        perror("Failed to init graphics");
        goto fail;
    }
    gpiokeys_init();
//    ezfb_find_off_screen();
    scrollback_init(29, 80, fb.mid_x-320, fb.mid_y - 225);
    ezfb_clear_screen(&fb);
    refresh_default();
    printf("Initialized...\n");
    append_log("Initialized...");
    prepare_loopfs();
    append_log("Adding temporary test file to loopback");
    append_log("Opening file %s", TMP_MOUNT_PATH "/thefile.txt");
    unsigned int myfd = open(TMP_MOUNT_PATH "/thefile.txt", O_RDWR | O_CREAT, 0);
    append_log("Opening file with fd %d", myfd);
    if(myfd >= 0)
    {
        if(write(myfd, "Test\n", 5) != 5)
            append_log("Error writing: %s", strerror(errno));
        close(myfd);
        append_log("Done adding temp file");
    } else append_log("Error opening: %s", strerror(errno));

    disable_loopfs();
    enable_usbfs();
    int key;
    append_log("Please copy files now!");
    append_log("Press power to reboot back into android");
    while((key = gpiokeys_getkey()) != KEY_POWER)
    {
/*       printf("Key: %d\n", key);
        if(key == KEY_VOLUMEUP)
            append_log("Button VolumeUp pressed");
        else
            append_log("Button VolumeDown Pressed");*/
    }
    disable_usbfs();
    printf("Last key?\n");
    goto end;
fail:
/*    unlink(DESTBLOB);
    unlink(DESTBCTC);
    unlink(DESTBCTR);
    unlink(DESTEBT);*/
end:
/*    close(bctr);
    close(bctc);
    close(blob);
    close(blout);
    close(log);*/

    ezfb_release(&fb);

    if(!strncmp(argv[0], "/init", 5)) {
        sync();
/*        mount(DATADEV, DATADIR, DATAFS, MS_REMOUNT | MS_RDONLY, "");
        umount2(DATADEV, MNT_FORCE);*/
        reboot(RB_AUTOBOOT);
    }

    EZFB_FUNCTION_RETURN(!ret)
}
