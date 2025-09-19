//
//  VoltageShift.h
//
//  Created by SC Lee on 12/09/13.
//  Copyright (c) 2017 SC Lee . All rights reserved.
//
//  MSR Kext Access modified from AnVMSR by Andy Vandijck Copyright (C) 2013 AnV Software
//
//  This is licensed under the GNU General Public License v3.0
//

#ifndef VoltageShift_hpp
#define VoltageShift_hpp

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <pexpert/pexpert.h>
#include <string.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/libkern.h>

#if TARGET_CPU_X86_64
#include <i386/proc_reg.h>
#endif /* TARGET_CPU_X86_64 */

#define BUFSIZE 512 /* bytes */
#define MAXENTRIES 500
#define MAXUSERS 5

#define DEBUG 1

#define kMethodObjectUserClient ((IOService *) 0)

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

class AnVMSRUserClient;

class VoltageShift : public IOService {
    OSDeclareDefaultStructors(VoltageShift)

public:
    virtual bool init(OSDictionary *dictionary = 0) override;
    virtual void free(void) override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual uint64_t a_rdmsr(uint32_t msr);
    virtual void a_wrmsr(uint32_t msr, uint64_t value);
    virtual IOReturn runAction(UInt32 action, UInt32 *outSize, void **outData, void *extraArg);
    virtual IOReturn newUserClient(task_t owningTask, void *securityID, UInt32 type, IOUserClient **handler) override;
    virtual void setErr(bool set);
    virtual void closeChild(AnVMSRUserClient *ptr);

    size_t mPrefPanelMemoryBufSize;
    uint32_t mPrefPanelMemoryBuf[2];
    UInt16 mClientCount;
    bool mErrFlag;
    AnVMSRUserClient *mClientPtr[MAXUSERS + 1];
};

class AnVMSRUserClient : public IOUserClient {
    OSDeclareDefaultStructors(AnVMSRUserClient);

private:
    VoltageShift *mDevice;

public:
    void messageHandler(UInt32 type, const char *format, ...) __attribute__((format (printf, 3, 4)));

    static const AnVMSRUserClient *withTask(task_t owningTask);

    virtual void free() override;
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual bool initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) override;
    virtual IOReturn clientClose() override;
    virtual IOReturn clientDied() override;
    virtual bool set_Q_Size(UInt32 capacity);
    virtual bool willTerminate(IOService *provider, IOOptionBits options) override;
    virtual bool didTerminate(IOService *provider, IOOptionBits options, bool *defer) override;
    virtual bool terminate(IOOptionBits options = 0) override;
    virtual IOExternalMethod *getTargetAndMethodForIndex(IOService **targetP, UInt32 index) override;
    virtual IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) override;
    virtual IOReturn actionMethodRDMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize);
    virtual IOReturn actionMethodWRMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize);
    virtual IOReturn actionMethodPrepareMap(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize);

    task_t fTask;
    /* Remove IODataQueue because of security issue recommend by Apple */
    int Q_Err;
    UInt64 LastMapAddr, LastMapSize;
};

#endif /* VoltageShift_hpp */
