//
//  main.mm
//
//  Created by SC Lee on 12/09/13.
//  Copyright (c) 2017 SC Lee . All rights reserved.
//
//  MSR Kext Access modified from AnVMSR by Andy Vandijck Copyright (C) 2013 AnV Software
//
//  This is licensed under the GNU General Public License v3.0
//

#import <Foundation/Foundation.h>
#import <sstream>
#import <vector>

#include "TargetConditionals.h"

/* SET TRUE WHEN YOUR SYSTEM REQUIRE OFFSET */
#define OFFSET_TEMP 0
#define DEBUG 1

#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* MAP_FAILED */

#define kAnVMSRClassName "VoltageShift"

#define MSR_OC_MAILBOX 0x150
#define MSR_OC_MAILBOX_CMD_OFFSET 32
#define MSR_OC_MAILBOX_RSP_OFFSET 32
#define MSR_OC_MAILBOX_DOMAIN_OFFSET 40
#define MSR_OC_MAILBOX_BUSY_BIT 63
#define OC_MAILBOX_READ_VOLTAGE_CMD 0x10
#define OC_MAILBOX_WHITE_VOLTAGE_CMD 0x11
#define OC_MAILBOX_VALUE_OFFSET 20
#define OC_MAILBOX_RETRY_COUNT 5

io_connect_t connect;
Boolean damagemode = false;

io_service_t service;

double basefreq = 0;
double maxturbofreq = 0;
double multturbofreq = 0;
double fourthturbofreq = 0;
double sixthturbofreq = 0;
double eightthturbofreq = 0;
double power_units = 0;
uint64 dtsmax = 0;
uint64 tempoffset = 0;
bool isUnloadOnEnd = false;

enum {
    AnVMSRActionMethodRDMSR = 0,
    AnVMSRActionMethodWRMSR = 1,
    AnVMSRActionMethodPrepareMap = 2,
    AnVMSRNumMethods
};

typedef struct {
    UInt32 action;
    UInt32 msr;
    UInt64 param;
} inout;

typedef struct {
    UInt64 addr;
    UInt64 size;
} map_t;

io_service_t getService() {
    io_service_t service = 0;
    mach_port_t masterPort;
    io_iterator_t iter;
    kern_return_t ret;
    io_string_t path;

    ret = IOMasterPort(MACH_PORT_NULL, &masterPort);
    if (ret != KERN_SUCCESS) {
        printf("Can't get masterport\n");
        goto failure;
    }

    ret = IOServiceGetMatchingServices(masterPort, IOServiceMatching(kAnVMSRClassName), &iter);
    if (ret != KERN_SUCCESS) {
        printf("VoltageShift.kext is not running\n");
        goto failure;
    }

    service = IOIteratorNext(iter);
    IOObjectRelease(iter);

    ret = IORegistryEntryGetPath(service, kIOServicePlane, path);
    if (ret != KERN_SUCCESS) {
        goto failure;
    }

failure:
    return service;
}

void usage(const char *name) {
    printf("------------------------------------------------------------------------\n");
    printf("VoltageShift Undervoltage Tool v1.30 for Intel Haswell/Broadwell\n");
    printf("Copyright (C) 2020 SC Lee\n");
    printf("------------------------------------------------------------------------\n");
    printf("Usage:\n");
    printf("Set voltage:\n   %s offset <CPU> <GPU> <CPUCache> <SA> <AI/O> <DI/O>\n\n", name);
    printf("Set boot and auto apply:\n   sudo %s buildlaunchd <CPU> <GPU> <CPUCache> <SA> <AI/O> <DI/O> <turbo> <pl1> <pl2> <remain> <UpdateMins (0 only apply at bootup)>\n\n", name);
    printf("Remove boot and auto apply:\n   %s removelaunchd\n\n", name);
    printf("Get info of current setting:\n   %s info\n\n", name);
    printf("Continuous monitor of CPU:\n   %s mon\n\n", name);
    printf("Set Power Limit: %s power <PL1> <PL2>\n\n", name);
    printf("Set Turbo Disabled/Enabled: %s turbo <0/1>\n\n", name);
    printf("Read MSR: %s read <HEX_MSR>\n\n", name);
    printf("Write MSR: %s write <HEX_MSR> <HEX_VALUE>\n\n", name);
    printf("Read memory: %s rdmem <HEX_ADDR>\n\n", name);
    printf("Write memory: %s wrmem <HEX_ADDR> <HEX_VALUE>\n\n", name);
}

unsigned long long hex2int(const char *s) {
    return strtoull(s, NULL, 16);
}

void printBits(size_t const size, void const *const ptr) {
    unsigned char *b = (unsigned char *) ptr;
    unsigned char byte;
    unsigned long int i, j;
    printf("(");

    for (i = size - 1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }

        if (i != 0)
            printf(" ");
        else
            puts(")");
    }
}

/*
 * Read OC Mailbox
 * Ref of Intel Turbo Boost Max Technology 3.0 legacy (non HWP) enumeration driver :
 * https://github.com/torvalds/linux/blob/master/drivers/platform/x86/intel_turbo_max_3.c
 *
 * offset 0x40 is the OC Mailbox Domain bit relative for:
 *    domain : 0 - CPU
 *             1 - GPU
 *             2 - CPU Cache
 *             3 - System Agency
 *             4 - Analogy I/O
 *             5 - Digital I/O
*/

int writeOCMailBox(int domain, int offset) {
    if (offset > 0 && !damagemode) {
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift offset Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("Your settings require overclocking. This May Damage you Computer !!!!\n");
        printf("use --damaged for override\n");
        printf("usage: voltageshiftd --damage offset ... for run\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("------------------------------------------------------------------------\n");

        return -1;
    }

    if (offset < -250 && !damagemode) {
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift offset Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("Your settings are too low. Are you sure you want those values\n");
        printf("use --damaged for override\n");
        printf("usage: voltageshiftd --damage offset ... for run\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        printf("------------------------------------------------------------------------\n");

        return -1;
    }

    if (damagemode) {
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift offset Tool Damage Mode in Process\n");
        printf("------------------------------------------------------------------------\n");
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }

    uint64 offsetvalue;

    if (offset < 0) {
        offsetvalue = 0x1000 + ((offset) * 2);
    }
    else {
        offsetvalue = offset * 2;
    }

    uint64 value = offsetvalue << OC_MAILBOX_VALUE_OFFSET;
    /* MSR 0x150 OC Mailbox 0x11 for write of voltage offset values */
    uint64 cmd = OC_MAILBOX_WHITE_VOLTAGE_CMD;
    int ret;

    inout in;
    inout out;
    size_t outsize = sizeof(out);
    /* Issue favored core read command */
    value |= cmd << MSR_OC_MAILBOX_CMD_OFFSET;
    /* Domain for the values set for */
    value |= ((uint64)domain) << MSR_OC_MAILBOX_DOMAIN_OFFSET;
    /* Set the busy bit to indicate OS is trying to issue command */
    value |= ((uint64)0x1) << MSR_OC_MAILBOX_BUSY_BIT;

    in.msr = (UInt32)MSR_OC_MAILBOX;
    in.action = AnVMSRActionMethodWRMSR;
    in.param = value;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodWRMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("CPU OC mailbox write failed\n");
        return 0;
    }

    return 0;
}

int readOCMailBox(int domain) {
    /* MSR 0x150 OC Mailbox 0x10 for read of voltage offset values */
    uint64 value, cmd = OC_MAILBOX_READ_VOLTAGE_CMD;
    int ret, i;

    inout in;
    inout out;
    size_t outsize = sizeof(out);
    /* Issue favored core read command */
    value = cmd << MSR_OC_MAILBOX_CMD_OFFSET;
    /* Domain for the values set for */
    value |= ((uint64)domain) << MSR_OC_MAILBOX_DOMAIN_OFFSET;
    /* Set the busy bit to indicate OS is trying to issue command */
    value |= ((uint64)0x1) << MSR_OC_MAILBOX_BUSY_BIT;

    in.msr = (UInt32)MSR_OC_MAILBOX;
    in.action = AnVMSRActionMethodWRMSR;
    in.param = value;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodWRMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("CPU OC mailbox write failed\n");
        return 0;
    }

    for (i = 0; i < OC_MAILBOX_RETRY_COUNT; ++i) {
        in.msr = MSR_OC_MAILBOX;
        in.action = AnVMSRActionMethodRDMSR;
        in.param = 0;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read voltage 0x00e7\n");
        }

        if (out.param & (((uint64)0x1) << MSR_OC_MAILBOX_BUSY_BIT)) {
            printf("OC mailbox still processing\n");
            ret = -EBUSY;
            continue;
        }
        if ((out.param >> MSR_OC_MAILBOX_RSP_OFFSET) & 0xff) {
            printf("OC mailbox cmd failed\n");
            break;
        }
        break;
    }

    int returnvalue = (int)(out.param >> 20) & 0xFFF;

    if (returnvalue > 2047) {
        returnvalue = -(0x1000 - returnvalue);
    }

    return returnvalue / 2;
}

int showcpuinfo() {
    kern_return_t ret;

    inout in;
    inout out;
    size_t outsize = sizeof(out);

    double freq = 0;
    double powerpkg = 0;
    double powercore = 0;
    bool oclocked = false;
    bool turbodisable = false;
    double p1power = 0;
    double p2power = 0;

    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;

    if (p1power == 0) {
        in.msr = 0x610;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x0610");
            return (1);
        }
        p1power = (double)(out.param & 0x7FFF) / 8;
        p2power = (double)(out.param >> 32 & 0x7FFF) / 8;
    }

    if (turbodisable == false) {
        in.msr = 0x1a0;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x01a0");
            return (1);
        }
        turbodisable = ((out.param >> 38 & 0x1) == 1);
    }

    if (oclocked == false) {
        in.msr = 0x194;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x0194");
            return (1);
        }
        oclocked = ((out.param >> 20 & 0x1) == 1);
    }

    if (basefreq == 0) {
        in.msr = 0xce;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x00ce");
            return (1);
        }
        basefreq = (double)(out.param >> 8 & 0xFF) * 100;
    }

    if (power_units == 0) {
        in.msr = 0x606;
        in.action = AnVMSRActionMethodRDMSR;
        in.param = 0;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x0606");
            return (1);
        }
        power_units = pow(0.5, (double)((out.param >> 8) & 0x1f)) * 10;
    }

    if (maxturbofreq == 0) {
        in.msr = 0x1AD;
        in.action = AnVMSRActionMethodRDMSR;
        in.param = 0;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x01ad");
            return (1);
        }

        maxturbofreq = (double)(out.param & 0xff) * 100.0;
        multturbofreq = (double)(out.param >> 8 & 0xff) * 100.0;
        fourthturbofreq = (double)(out.param >> 24 & 0xff) * 100.0;
        sixthturbofreq = (double)(out.param >> 40 & 0xff) * 100.0;
        eightthturbofreq = (double)(out.param >> 56 & 0xff) * 100.0;
        if (eightthturbofreq != 0) {
            printf("CPU BaseFreq: %.0f, CPU MaxFreq(1/2/4/6/8): %.0f/%.0f/%.0f/%.0f/%.0f (mhz)\n", basefreq, maxturbofreq, multturbofreq, fourthturbofreq, sixthturbofreq, eightthturbofreq);
        }
        else if (sixthturbofreq != 0) {
            printf("CPU BaseFreq: %.0f, CPU MaxFreq(1/2/4/6): %.0f/%.0f/%.0f/%.0f (mhz)\n", basefreq, maxturbofreq, multturbofreq, fourthturbofreq, sixthturbofreq);
        }
        else {
            printf("CPU BaseFreq: %.0f, CPU MaxFreq(1/2/4): %.0f/%.0f/%.0f (mhz)", basefreq, maxturbofreq, multturbofreq, fourthturbofreq);
        }

        printf("%s %s PL1: %.0fW PL2: %.0fW\n", oclocked ? "OC_Locked" : "", turbodisable ? "Turbo_Disabled" : "", p1power, p2power);
    }

    in.msr = 0x611;
    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read 0x0611");
        return (1);
    }

    unsigned long long lastpowerpkg = out.param;

    in.msr = 0x639;
    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read 0x0639");
        return (1);
    }

    unsigned long long lastpowercore = out.param;

    uint64 firsttime;
    firsttime = clock_gettime_nsec_np(CLOCK_REALTIME) / 1000;
    usleep(100000);

    uint64 secondtime;
    secondtime = clock_gettime_nsec_np(CLOCK_REALTIME) / 1000;
    secondtime -= firsttime;
    double second = (double)secondtime / 100000;

    in.msr = 0x611;
    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read power 0x0611");
        return (1);
    }

    powerpkg = power_units * ((double)out.param - lastpowerpkg) / second;

    in.msr = 0x639;
    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read 0x0639");
        return (1);
    }

    powercore =  power_units * ((double)out.param - lastpowercore) / second;

    in.msr = 0x198;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read voltage 0x0198\n");
        return (1);
    }

    double voltage = out.param >> 32 & 0xFFFF;
    freq = out.param >> 8 & 0xFF;
    freq /= 10;
    voltage /= pow(2, 13);

    if (dtsmax == 0) {
        in.msr = 0x1A2;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read voltage 0x01A2\n");
            return (1);
        }
        dtsmax = out.param >> 16 & 0xFF;
        tempoffset = out.param >> 24 & 0x3F;
    }

    in.msr = 0x19C;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't read voltage 0x019C\n");
        return (1);
    }

    uint64 margintothrottle = out.param >> 16 & 0x3F;
    uint64 temp = dtsmax - margintothrottle;

    if (OFFSET_TEMP)
        temp -= tempoffset;

    printf("CPU Freq: %2.1fghz, Voltage: %.4fv, Power:pkg %2.2fw /core %2.2fw, Temp: %llu c", freq, voltage, powerpkg, powercore, temp);

    return (0);
}

int setPower(int argc, int p1, int p2) {
    inout in;
    inout out;
    size_t outsize = sizeof(out);

    kern_return_t ret;

    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;

    double p1power = 0;
    double p2power = 0;

    if (p1power == 0) {
        in.msr = 0x610;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x0610");
            return (1);
        }
        p1power = (double)(out.param & 0x7FFF) / 8;
        p2power = (double)(out.param >> 32 & 0x7FFF) / 8;
    }

    printf("Current Setting: PL1(Long term): %.fW, PL2(Short term) %.fW\n", p1power, p2power);

    if (argc <= 3) {
        return (1);
    }

    if (p1 == -1 || p2 == -1) {
        return (1);
    }
    if (p1 < 5 * 8 || p2 < 5 * 8) {
        printf("your setting may too low, at least 5W\n");
        return (1);
    }

    for (int i = 0; i < 15; i++) {
        out.param ^= (-(p1 >> i & 0x1) ^ out.param) & (1UL << i);
    }
    for (int i = 32; i < 47; i++) {
        out.param ^= (-(p2 >> i & 0x1) ^ out.param) & (1UL << i);
    }

    in.action = AnVMSRActionMethodWRMSR;
    in.param = out.param;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodWRMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't connect to StructMethod to send commands\n");
    }
    else {
        printf("Modified Setting: PL1(Long term): %dW, PL2(Short term) %dW\n", p1 / 8, p2 / 8);
    }

    return 1;
}

int setPower(int argc, const char *argv[]) {
    int p1 = 0;
    int p2 = 0;

    if (argc <= 3) {
        printf("%s power <PL1> <PL2>\n", argv[0]);
        printf("PL1 - long term power limited\n");
        printf("PL2 - short term power limited\n");
    }
    else {
        p1 = (int)strtol((char *)argv[2], NULL, 10) * 8;
        p2 = (int)strtol((char *)argv[3], NULL, 10) * 8;
    }

    return setPower(argc, p1, p2);
}

int setTurbo(int argc, bool enable) {
    inout in;
    inout out;
    size_t outsize = sizeof(out);

    in.action = AnVMSRActionMethodRDMSR;
    in.param = 0;
    bool turbodisabled = false;
    kern_return_t ret;

    if (turbodisabled == false) {
        in.msr = 0x1a0;
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't read 0x01a0");
            return (1);
        }
        turbodisabled = (out.param >> 38 & 0x1) > 0 ? true : false;
    }

    printf("Current Setting: Turbo Boost **%s\n", turbodisabled ? "Disabled" : "Enabled");

    if (argc <= 2) {
        return (0);
    }

    if (enable)
        turbodisabled = 1;
    else
        turbodisabled = 0;

    out.param ^= (-(turbodisabled ? 1 : 0 >> (38 & 0x1)) ^ out.param) & (1UL << 38);
    // out.param = turbodisabled ? 0x4000850089 : 0x850089;

    in.action = AnVMSRActionMethodWRMSR;
    in.param = out.param;
    ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodWRMSR, &in, sizeof(in), &out, &outsize);
    if (ret != KERN_SUCCESS) {
        printf("Can't connect to StructMethod to send commands\n");
    }
    else {
        printf("Modified Setting: Turbo Boost **%s\n", turbodisabled ? "Disabled" : "Enabled");
    }

    return 1;
}

int setTurbo(int argc, const char *argv[]) {
    bool enable = true;

    if (argc <= 2) {
        printf("------------------------------------------------------------------------\n");
        printf("%s turbo 0\n", argv[0]);
        printf("for disable Intel turbo\n");
        printf("%s turbo 1\n", argv[0]);
        printf("for enable Intel turbo\n");
        printf("------------------------------------------------------------------------\n");
    }
    else {
        enable = (int)strtol((char *)argv[2], NULL, 10) == 0;
    }

    return setTurbo(argc, enable);
}

int setoffsetdaemons(int argc, const char *argv[]) {
    int p1 = 0;

    for (int i = 0; i < argc - 2; i++) {
        /* Set turbo */
        if (i == 6) {
            int value = (int)strtol((char *)argv[i + 2], NULL, 10);
            if (value >= 0)
                setTurbo(3, value == 0);
            continue;
        }
        if (i == 7) {
            p1 = (int)strtol((char *)argv[i + 2], NULL, 10) * 8;
            continue;
        }
        if (i == 8) {
            if (p1 != 0) {
                int p2 = (int)strtol((char *)argv[i + 2], NULL, 10) * 8;
                setPower(4, p1, p2);
            }
            continue;
        }
        if (i == 9) {
            p1 = (int)strtol((char *)argv[i + 2], NULL, 10) * 8;
            if (p1)
                isUnloadOnEnd = false;
        }

        int offset = (int)strtol((char *)argv[i + 2], NULL, 10);

        if (readOCMailBox(i) != offset) {
            writeOCMailBox(i, offset);
        }
    }

    return (0);
}

int setoffset(int argc, const char *argv[]) {
    long cpu_offset = 0;
    long gpu_offset = 0;
    long cpuccache_offset = 0;
    long systemagency_offset = 0;
    long analogy_offset = 0;
    long digitalio_offset = 0;

    if (argc >= 3) {
        cpu_offset = strtol((char *)argv[2], NULL, 10);

        if (argc >= 4)
            gpu_offset = strtol((char *)argv[3], NULL, 10);
        if (argc >= 5)
            cpuccache_offset = strtol((char *)argv[4], NULL, 10);
        if (argc >= 6)
            systemagency_offset = strtol((char *)argv[5], NULL, 10);
        if (argc >= 7)
            analogy_offset = strtol((char *)argv[6], NULL, 10);
        if (argc >= 8)
            digitalio_offset = strtol((char *)argv[7], NULL, 10);
    }
    else {
        usage(argv[0]);
        return (1);
    }

    printf("------------------------------------------------------------------------\n");
    printf("VoltageShift offset Tool\n");
    printf("------------------------------------------------------------------------\n");

    if (argc >= 3)
        printf("Before CPU voltageoffset: %dmv\n", readOCMailBox(0));
    if (argc >= 4)
        printf("Before GPU voltageoffset: %dmv\n", readOCMailBox(1));
    if (argc >= 5)
        printf("Before CPU Cache: %dmv\n", readOCMailBox(2));
    if (argc >= 6)
        printf("Before System Agency: %dmv\n", readOCMailBox(3));
    if (argc >= 7)
        printf("Before Analogy I/O: %dmv\n", readOCMailBox(4));
    if (argc >= 8)
        printf("Before Digital I/O: %dmv\n", readOCMailBox(5));

    printf("------------------------------------------------------------------------\n");

    if (argc >= 3)
        writeOCMailBox(0, (int)cpu_offset);
    if (argc >= 4)
        writeOCMailBox(1, (int)gpu_offset);
    if (argc >= 5)
        writeOCMailBox(2, (int)cpuccache_offset);
    if (argc >= 6)
        writeOCMailBox(3, (int)systemagency_offset);
    if (argc >= 7)
        writeOCMailBox(4, (int)analogy_offset);
    if (argc >= 8)
        writeOCMailBox(5, (int)digitalio_offset);

    if (argc >= 3)
        printf("After CPU voltageoffset: %dmv\n", readOCMailBox(0));
    if (argc >= 4)
        printf("After GPU voltageoffset: %dmv\n", readOCMailBox(1));
    if (argc >= 5)
        printf("After CPU Cache: %dmv\n", readOCMailBox(2));
    if (argc >= 6)
        printf("After System Agency: %dmv\n", readOCMailBox(3));
    if (argc >= 7)
        printf("After Analogy I/O: %dmv\n", readOCMailBox(4));
    if (argc >= 8)
        printf("After Digital I/O: %dmv\n", readOCMailBox(5));

    printf("------------------------------------------------------------------------\n");

    return (0);
}

void unloadkext() {
    if (!isUnloadOnEnd)
        return;

    if (connect) {
        kern_return_t ret = IOServiceClose(connect);
        if (ret != KERN_SUCCESS) {
        }
    }
    if (service)
        IOObjectRelease(service);

    std::stringstream output;
    output << "sudo kextunload -q -b"
    << "com.sicreative.VoltageShift"
    << " ";
    system(output.str().c_str());
}

void loadkext() {
    isUnloadOnEnd = true;

    std::stringstream output;
    output << "sudo kextutil -q -r ./ -b"
    << "com.sicreative.VoltageShift"
    << " ";
    system(output.str().c_str());
    output.str("");
    output << "sudo kextutil -q -r /Library/Application\\ Support/VoltageShift/ -b"
    << "com.sicreative.VoltageShift"
    << " ";
    system(output.str().c_str());
}

void removeLaunchDaemons() {
    std::stringstream output;
    output.str("sudo launchctl unload /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    system(output.str().c_str());
    output.str("sudo rm -rf /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    system(output.str().c_str());
    output.str("sudo rm -rf /Library/Application\\ Support/VoltageShift");
    system(output.str().c_str());
    /* Check process of build sucessful */
    int error = 0;

    FILE *fp = popen("sudo ls /Library/LaunchDaemons/com.sicreative.VoltageShift.plist", "r");
    if (fp != NULL) {
        char str[255];
        while (fgets(str, 255, fp) != NULL) {
            printf("%s", str);
            if (strstr(str, "/Library/LaunchDaemons/com.sicreative.VoltageShift.plist") != NULL) {
                error++;
            }
        }
        pclose(fp);
    }

    fp = popen("sudo ls /Library/Application\\ Support/VoltageShift/", "r");
    if (fp != NULL) {
        char str[255];
        while (fgets(str, 255, fp) != NULL) {
            printf("%s", str);
            if (strstr(str, "VoltageShift.kext") != NULL) {
                error++;
                continue;
            }
            if (strstr(str, "voltageshiftd") != NULL) {
                error++;
            }
        }
        pclose(fp);
    }
    /* Error Messages */
    if (error != 0) {
        printf("\n\n\n\n\n");
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift remove Launchd daemons Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("Can't Remove the launchd. No Sucessful of delete the files,\n");
        printf("or manual delete by:\n");
        printf("sudo launchctl unload /Library/LaunchDaemons/com.sicreative.VoltageShift.plist\n");
        printf("sudo rm -rf /Library/LaunchDaemons/com.sicreative.VoltageShift.plist\n");
        printf("sudo rm -rf /Library/Application\\ Support/VoltageShift\n");
        printf("------------------------------------------------------------------------\n");

        return;
    }

    printf("\n\n\n\n\n");
    printf("------------------------------------------------------------------------\n");
    printf("VoltageShift remove Launchd daemons Tool\n");
    printf("------------------------------------------------------------------------\n");
    printf("Sucessed Full remove the Launchd daemons\n");
    printf("Fully Switch off (no reboot) for the system back to non-undervoltage status\n");
    printf("------------------------------------------------------------------------\n");
    printf("Don't forget enable the CSR protect by following methond:\n");
    printf("1. Boot start by Command-R to recovery mode:\n");
    printf("2. In \"Terminal\" >> csrutil enable\n");
    printf("------------------------------------------------------------------------\n");
}

void writeLaunchDaemons(std::vector<int> values = {0}, int min = 160) {
    std::stringstream output;

    if (min > 720) {
        printf("------------------------------------------------------------------------\n");
        printf("Out of Interval setting, please select between 0 (Run only bootup) to 720mins\n");
        printf("------------------------------------------------------------------------\n");

        return;
    }

    printf("Build for LaunchDaemons of Auto Apply for VoltageShift\n");
    printf("------------------------------------------------------------------------\n");
    output.str("sudo launchctl unload /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    output.str("sudo rm -rf /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    output.str("sudo rm -rf /Library/Application\\ Support/VoltageShift");
    system(output.str().c_str());
    output.str("");
    /* add 0 for no user input field */
    for (int i = (int)values.size(); i <= 5; i++) {
        values.push_back(0);
    }
    /* Build LaunchDaemons */
    output << "sudo echo \""
    << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
    << "<plist version=\"1.0\">"
    << "<dict>"
    << "<key>RunAtLoad</key><true/>"
    << "<key>Label</key>"
    << "<string>com.sicreative.VoltageShift</string>"
    << "<key>ProgramArguments</key>"
    << "<array>"
    << "<string>/Library/Application Support/VoltageShift/voltageshiftd</string>"
    << "<string>offsetdaemons</string>";

    for (int i = 0; i < values.size(); i++) {
        output << "<string>"
        << values[i]
        << "</string>";
    }
    output << "</array>";

    if (min > 0) {
        output << "<key>StartCalendarInterval</key>"
        << "<array>";
        if (min <= 60 && 60 % min == 0) {
            for (int i = 0; i < 60; i += min) {
                output << "<dict>"
                << "<key>Minute</key>"
                << "<integer>"
                << i
                << "</integer>"
                << "</dict>";
            }
        }
        else {
            for (int i = 0; i < 1440; i += min) {
                output << "<dict>"
                << "<key>Hour</key>"
                << "<integer>"
                << i / 60
                << "</integer>"
                << "<key>Minute</key>"
                << "<integer>"
                << i % 60
                << "</integer>"
                << "</dict>";
            }
        }
        output << "</array>";
    }
    output << "</dict>"
    << "</plist>"
    << "\" > /Library/LaunchDaemons/com.sicreative.VoltageShift.plist"
    << " ";
    /* Set permissions and copy */
    system(output.str().c_str());
    output.str("sudo chmod 644 /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    system(output.str().c_str());
    output.str("sudo chown root:wheel /Library/LaunchDaemons/com.sicreative.VoltageShift.plist");
    system(output.str().c_str());
    output.str("sudo mkdir -p /Library/Application\\ Support/VoltageShift");
    system(output.str().c_str());
    output.str("sudo cp -R ./VoltageShift.kext /Library/Application\\ Support/VoltageShift/");
    system(output.str().c_str());
    output.str("sudo cp ./voltageshiftd /Library/Application\\ Support/VoltageShift/");
    system(output.str().c_str());
    output.str("sudo chown -R root:wheel /Library/Application\\ Support/VoltageShift/VoltageShift.kext");
    system(output.str().c_str());
    output.str("sudo chmod 755 /Library/Application\\ Support/VoltageShift/voltageshiftd");
    system(output.str().c_str());
    output.str("sudo chown root:wheel /Library/Application\\ Support/VoltageShift/voltageshiftd");
    system(output.str().c_str());
    /* Check process of build sucessful */
    int error = 3;

    FILE *fp = popen("sudo ls /Library/LaunchDaemons/com.sicreative.VoltageShift.plist", "r");
    if (fp != NULL) {
        char str[255];
        while (fgets(str, 255, fp) != NULL) {
            printf("%s", str);
            if (strstr(str, "/Library/LaunchDaemons/com.sicreative.VoltageShift.plist") != NULL) {
                error--;
            }
        }
        pclose(fp);
    }

    fp = popen("sudo ls /Library/Application\\ Support/VoltageShift/", "r");
    if (fp != NULL) {
        char str[255];
        while (fgets(str, 255, fp) != NULL) {
            printf("%s", str);

            if (strstr(str, "VoltageShift.kext") != NULL) {
                error--;
                continue;
            }
            if (strstr(str, "voltageshiftd") != NULL) {
                error--;
            }
        }
        pclose(fp);
    }
    /* Error Messages */
    if (error != 0) {
        printf("\n\n\n\n\n");
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift builddaemons Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("Can't build the launchd. Can´t create the files, please use:\n");
        printf("sudo ./voltageshiftd buildlaunchd ....\n");
        printf("for Root privilege.\n");
        printf("------------------------------------------------------------------------\n");

        return;
    }
    /* Sucess and Caution Messages */
    printf("\n\n\n\n\n");
    printf("------------------------------------------------------------------------\n");
    printf("VoltageShift builddaemons Tool\n");
    printf("------------------------------------------------------------------------\n");
    printf("Finished installing the LaunchDaemons, Please Reboot\n\n");
    printf("------------------------------------------------------------------------\n");
    printf("The system will apply the below undervoltage setting values for boot, and Amend every %d mins\n", min);
    printf("------------------------------------------------------------------------\n");
    printf("************************************************************************\n");
    printf("Please CONFIRM and TEST the system STABILITY in the below settings,\n otherwise REMOVE this launchd IMMEDIATELY\n");
    printf("You can remove this by using: ./voltageshiftd removelaunchd\n");
    printf("Or manual remove by:\n");
    printf("sudo launchctl unload /Library/LaunchDaemons/com.sicreative.VoltageShift.plist\n");
    printf("sudo rm -rf /Library/LaunchDaemons/com.sicreative.VoltageShift.plist\n");
    printf("sudo rm -rf /Library/Application\\ Support/VoltageShift\n");
    printf("------------------------------------------------------------------------\n");
    printf("CPU             %d %s mv\n", values[0], values[0] > 0 ? "!!!!!" : "");
    printf("GPU             %d %s mv\n", values[1], values[1] > 0 ? "!!!!!" : "");
    printf("CPU Cache       %d %s mv\n", values[2], values[2] > 0 ? "!!!!!" : "");
    printf("System Agency   %d %s mv\n", values[3], values[3] > 0 ? "!!!!!" : "");
    printf("Analog IO       %d %s mv\n", values[4], values[4] > 0 ? "!!!!!" : "");
    printf("Digital IO      %d %s mv\n", values[5], values[5] > 0 ? "!!!!!" : "");

    if (values.size() >= 7 && values[6] >= 0)
        printf("Turbo   %s \n", values[6] > 0 ? "Enable" : "Disable");
    if (values.size() >= 9 && values[7] >= 0 && values[8] >= 0)
        printf("Power   %d  %d  \n", values[7], values[8]);
    if (values.size() >= 10 && values[9] >= 0)
        printf("The kext will %sremain on System when unload\n", values[9] > 0 ? "" : "not");
    /* End Messages */
    printf("------------------------------------------------------------------------\n");
    printf("************************************************************************\n");
    printf("Please notice if you cannot boot the system after installing, you need to:\n");
    printf("1. Fully turn off Computer (not reboot):\n");
    printf("2. Boot start by Command-R to recovery mode:\n");
    printf("3. In \"Terminal\" Enable the CSR protection to stop undervoltage running when boot\n");
    printf("4. csrutil enable\n");
    printf("5. Reboot and Remove all file above\n");
    printf("------------------------------------------------------------------------\n");
}

void *map_physical(uint64_t phys_addr, size_t len) {
    kern_return_t err;

#if __LP64__
    mach_vm_address_t addr;
    mach_vm_size_t size;
#else
    vm_address_t addr;
    vm_size_t size;
#endif /* __LP64__ */

    size_t dataInLen = sizeof(map_t);
    size_t dataOutLen = sizeof(map_t);
    map_t in, out;

    in.addr = phys_addr;
    in.size = len;

#ifdef DEBUG
    printf("map_phys: phys %08llx, %08zx\n", phys_addr, len);
#endif /* DEBUG */

#if !defined(__LP64__) && defined(WANT_OLD_API)
    /* Check if OSX 10.5 API is available */
    if (IOConnectCallStructMethod != NULL) {
#endif /* !defined(__LP64__) && defined(WANT_OLD_API) */

        err = IOConnectCallStructMethod(connect, AnVMSRActionMethodPrepareMap, &in, dataInLen, &out, &dataOutLen);

#if !defined(__LP64__) && defined(WANT_OLD_API)
    }
    else {
        /* Use old API */
        err = IOConnectMethodStructureIStructureO(connect, kPrepareMap, dataInLen, &dataOutLen, &in, &out);
    }
#endif /* !defined(__LP64__) && defined(WANT_OLD_API) */

    if (err != KERN_SUCCESS) {
        printf("\nError(kPrepareMap): system 0x%x subsystem 0x%x code 0x%x ", err_get_system(err), err_get_sub(err), err_get_code(err));

        printf("physical 0x%08llx[0x%x]\n", phys_addr, (unsigned int)len);

        switch (err_get_code(err)) {
            case 0x2c2: printf("Invalid argument.\n"); errno = EINVAL; break;
            case 0x2cd: printf("Device not open.\n"); errno = ENOENT; break;
        }

        return MAP_FAILED;
    }

    err = IOConnectMapMemory(connect, 0, mach_task_self(), &addr, &size, kIOMapAnywhere | kIOMapInhibitCache);
    /* Now this is odd; The above connect seems to be unfinished at the
     * time the function returns. So wait a little bit, or the calling
     * program will just segfault. Bummer. Who knows a better solution?
     */
    usleep(1000);

    if (err != KERN_SUCCESS) {
        printf("\nError(IOConnectMapMemory): system 0x%x subsystem 0x%x code 0x%x ", err_get_system(err), err_get_sub(err), err_get_code(err));

        printf("physical 0x%08llx[0x%x]\n", phys_addr, (unsigned int)len);

        switch (err_get_code(err)) {
            case 0x2c2: printf("Invalid argument.\n"); errno = EINVAL; break;
            case 0x2cd: printf("Device not open.\n"); errno = ENOENT; break;
        }

        return MAP_FAILED;
    }

#ifdef DEBUG
    printf("map_phys: virt %08llx, %08llx\n", addr, size);
#endif /* DEBUG */

    return (void *)addr;
}

void unmap_physical(void *virt_addr __attribute__((unused)), size_t len __attribute__((unused))) {
    /* Nut'n Honey */
}

int access_direct_memory(uintptr_t addr, uint32_t *value, bool write) {
    /* align to a page boundary */
    const uintptr_t page_mask = 0xFFF;
    const size_t len = 4;
    const uintptr_t page_offset = addr & page_mask;
    const uintptr_t map_addr = addr & ~page_mask;
    const size_t map_len = (len + page_offset + page_mask) & ~page_mask;

    volatile uint8_t * const map_buf = (uint8_t *) map_physical(map_addr, map_len);
    if (map_buf == NULL) {
        printf("Map memory %08lx failed.", addr);
        return -1;
    }
    volatile uint8_t * const buf = map_buf + page_offset;

    if (!write) {
        *value = buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24;
    }
    else {
        buf[0] = (uint8_t) ((*value) & 0xFF);
        buf[1] = (uint8_t) (((*value) >> 8) & 0xFF);
        buf[2] = (uint8_t) (((*value) >> 16) & 0xFF);
        buf[3] = (uint8_t) (((*value) >> 24) & 0xFF);
    }

    return 0;
}

void intHandler(int sig) {
    char c;
    signal(sig, SIG_IGN);
    printf("\n quit? [y/n] ");
    c = getchar();
    if (c == 'y' || c == 'Y') {
        unloadkext();
        exit(0);
    }
    else
        signal(SIGINT, intHandler);
    /* Get new line character */
    getchar();
}

int main(int argc, const char *argv[]) {
#if TARGET_CPU_ARM64
    printf("\n\n\n\n\n");
    printf("------------------------------------------------------------------------\n");
    printf("VoltageShift Not supported for ARM (Apple Silicon)\n");
    printf("------------------------------------------------------------------------\n");

    return (1);
#endif /* TARGET_CPU_ARM64 */

    char *parameter;
    char *msr;
    char *regvalue;
    service = getService();

    if (argc >= 2) {
        parameter = (char *)argv[1];
    }
    else {
        usage(argv[0]);
        return (1);
    }

    int count = 0;
    while (!service && strncmp(parameter, "loadkext", 8) && strncmp(parameter, "unloadkext", 10)) {
        service = getService();

        if (!service)
            loadkext();

        count++;
        /* Try load 10 times, otherwise error return */
        if (count > 10)
            return (1);
    }

    kern_return_t ret;
    ret = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (ret != KERN_SUCCESS) {
        printf("Couldn't open IO Service\n");
    }

    if (argc >= 3) {
        msr = (char *)argv[2];
    }

    if (!strncmp(parameter, "info", 4)) {
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift Info Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("CPU voltage offset: %dmv\n", readOCMailBox(0));
        printf("GPU voltage offset: %dmv\n", readOCMailBox(1));
        printf("CPU Cache voltage offset: %dmv\n", readOCMailBox(2));
        printf("System Agency offset: %dmv\n", readOCMailBox(3));
        printf("Analogy I/O: %dmv\n", readOCMailBox(4));
        printf("Digital I/O: %dmv\n", readOCMailBox(5));
        showcpuinfo();
        printf("\n");
    }
    else if (!strncmp(parameter, "mon", 3)) {
        printf("------------------------------------------------------------------------\n");
        printf("VoltageShift Monitor Tool\n");
        printf("------------------------------------------------------------------------\n");
        printf("Ctl-C to Exit\n\n");
        signal(SIGINT, intHandler);
        printf("CPU voltage offset: %dmv\n", readOCMailBox(0));
        printf("GPU voltage offset: %dmv\n", readOCMailBox(1));
        printf("CPU Cache voltage offset: %dmv\n", readOCMailBox(2));
        printf("System Agency offset: %dmv\n", readOCMailBox(3));
        printf("Analogy I/O: %dmv\n", readOCMailBox(4));
        printf("Digital I/O: %dmv\n\n", readOCMailBox(5));
        /*
         *   domain : 0 - CPU
         *            1 - GPU
         *            2 - CPU Cache
         *            3 - System Agency
         *            4 - Analogy I/O
         *            5 - Digital I/O
         */
        do {
            if (showcpuinfo() > 0) {
                fflush(stdout);
                printf("\r");
                sleep(1);

                for (int i = 0; i < 5; i++) {
                    sleep(1);
                    loadkext();
                    service = getService();

                    kern_return_t ret;
                    ret = IOServiceOpen(service, mach_task_self(), 0, &connect);
                    if (ret != KERN_SUCCESS) {
                        printf("Couldn't open IO Service\n");
                        if (i == 4)
                            return (1);
                    }
                    else {
                        break;
                    }
                }
            }
            sleep(1);
            fflush(stdout);
            printf("\r");
        }
        while (true);
    }
    else if (!strncmp(parameter, "--damage", 8)) {
        if (argc >= 2) {
            if (!strncmp((char *)argv[2], "offset", 6)) {
                damagemode = true;

                std::vector<std::string> arg;
                arg.push_back(argv[0]);

                for (int i = 1; i < argc - 1; i++) {
                    arg.push_back(argv[i + 1]);
                }

                const char **arrayOfCstrings = new const char *[arg.size()];

                for (int i = 0; i < arg.size(); ++i)
                    arrayOfCstrings[i] = arg[i].c_str();

                setoffset(argc - 1, arrayOfCstrings);
            }
            else if (!strncmp((char *)argv[2], "offsetdaemons", 6)) {
                damagemode = true;

                std::vector<std::string> arg;
                arg.push_back(argv[0]);

                for (int i = 1; i < argc - 1; i++) {
                    arg.push_back(argv[i + 1]);
                }

                const char **arrayOfCstrings = new const char *[arg.size()];

                for (int i = 0; i < arg.size(); ++i)
                    arrayOfCstrings[i] = arg[i].c_str();

                setoffsetdaemons(argc - 1, arrayOfCstrings);
            }
            else {
                usage(argv[0]);
                return (1);
            }
        }
    }
    else if (!strncmp(parameter, "unloadkext", 10)) {
        isUnloadOnEnd = true;
        unloadkext();
    }
    else if (!strncmp(parameter, "loadkext", 8)) {
        loadkext();
        return 0;
    }
    else if (!strncmp(parameter, "removelaunchd", 13)) {
        removeLaunchDaemons();
    }
    else if (!strncmp(parameter, "buildlaunchd", 12)) {
        std::vector<int> arg;

        if (argc >= 3)
            arg.push_back((int)strtol((char *)argv[2], NULL, 10));
        if (argc >= 4)
            arg.push_back((int)strtol((char *)argv[3], NULL, 10));
        if (argc >= 5)
            arg.push_back((int)strtol((char *)argv[4], NULL, 10));
        if (argc >= 6)
            arg.push_back((int)strtol((char *)argv[5], NULL, 10));
        if (argc >= 7)
            arg.push_back((int)strtol((char *)argv[6], NULL, 10));
        if (argc >= 8)
            arg.push_back((int)strtol((char *)argv[7], NULL, 10));
        if (argc >= 9)
            arg.push_back((int)strtol((char *)argv[8], NULL, 10));
        if (argc >= 10)
            arg.push_back((int)strtol((char *)argv[9], NULL, 10));
        if (argc >= 11)
            arg.push_back((int)strtol((char *)argv[10], NULL, 10));
        if (argc >= 12)
            arg.push_back((int)strtol((char *)argv[11], NULL ,10));
        /* Write LaunchDaemons */
        if (argc >= 13)
            writeLaunchDaemons(arg, (int)strtol((char *)argv[12], NULL, 10));
        else {
            writeLaunchDaemons(arg);
        }
    }
    else if (!strncmp(parameter, "offsetdaemons", 12)) {
        setoffsetdaemons(argc, argv);
    }
    else if (!strncmp(parameter, "offset", 6)) {
        setoffset(argc, argv);
    }
    else if (!strncmp(parameter, "turbo", 5)) {
        setTurbo(argc, argv);
    }
    else if (!strncmp(parameter, "power", 5)) {
        setPower(argc, argv);
    }
    else if (!strncmp(parameter, "read", 4)) {
        inout in;
        inout out;
        size_t outsize = sizeof(out);

        in.msr = (UInt32)hex2int(msr);
        in.action = AnVMSRActionMethodRDMSR;
        in.param = 0;

#if MAC_OS_X_VERSION_MIN_REQUIRED <= MAC_OS_X_VERSION_10_4
        ret = IOConnectMethodStructureIStructureO(connect, AnVMSRActionMethodRDMSR, sizeof(in), &outsize, &in, &out);
#else
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodRDMSR, &in, sizeof(in), &out, &outsize);
#endif /* MAC_OS_X_VERSION_MIN_REQUIRED <= MAC_OS_X_VERSION_10_4 */

        if (ret != KERN_SUCCESS) {
            printf("Can't connect to StructMethod to send commands\n");
        }
        printBits(sizeof(out.param), &out.param);
    }
    else if (!strncmp(parameter, "write", 5)) {
        if (argc < 4) {
            usage(argv[0]);
            return (1);
        }

        inout in;
        inout out;
        size_t outsize = sizeof(out);

        regvalue = (char *)argv[3];

        in.msr = (UInt32)hex2int(msr);
        in.action = AnVMSRActionMethodWRMSR;
        in.param = hex2int(regvalue);
        ret = IOConnectCallStructMethod(connect, AnVMSRActionMethodWRMSR, &in, sizeof(in), &out, &outsize);
        if (ret != KERN_SUCCESS) {
            printf("Can't connect to StructMethod to send commands\n");
        }
    }
    else if (!strncmp(parameter, "rdmem", 5)) {
        UInt32 addr = (UInt32)hex2int(msr);
        uint32_t value = 0;
        if (access_direct_memory(addr, &value, false) != 0) {
            printf("read direct memory %x failed", addr);
        }
        else {
            printf("RDMEM %x returns value 0x%x\n", addr, value);
        }
    }
    else if (!strncmp(parameter, "wrmem", 5)) {
        if (argc < 4) {
            usage(argv[0]);
            return (1);
        }

        regvalue = (char *)argv[3];

        UInt32 addr = (UInt32)hex2int(msr);
        uint32_t value = (uint32_t)hex2int(regvalue);

        if (access_direct_memory(addr, &value, true) != 0) {
            printf("write direct memory %x with %x failed", addr, value);
        }
        else {
            access_direct_memory(addr, &value, false);
            printf("WRMEM %x returns value 0x%x\n", addr, value);
        }
    }
    else {
        usage(argv[0]);
        return (1);
    }

    if (connect) {
        ret = IOServiceClose(connect);
        if (ret != KERN_SUCCESS) {
        }
    }
    if (service)
        IOObjectRelease(service);

    unloadkext();

    return 0;
}
