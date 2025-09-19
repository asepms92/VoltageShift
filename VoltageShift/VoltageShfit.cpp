//
//  VoltageShift.cpp
//
//  Created by SC Lee on 12/09/13.
//  Copyright (c) 2017 SC Lee . All rights reserved.
//
//  MSR Kext Access modified from AnVMSR by Andy Vandijck Copyright (C) 2013 AnV Software
//
//  This is licensed under the GNU General Public License v3.0
//

#include "VoltageShift.h"

#define super IOService

OSDefineMetaClassAndStructors(VoltageShift, IOService)

bool VoltageShift::init(OSDictionary *dict) {
    bool res = super::init(dict);

#ifdef DEBUG
    IOLog("VoltageShift: Initializing...\n");
#endif /* DEBUG */

    return (res);
}

void VoltageShift::free() {
#ifdef DEBUG
    IOLog("VoltageShift: Freeing...\n");
#endif /* DEBUG */

    super::free();
}

bool VoltageShift::start(IOService *provider) {
    bool res = super::start(provider);

    registerService();
    IOLog("VoltageShift: Starting...\n");

    mPrefPanelMemoryBufSize = 4096;

    return (res);
}

void VoltageShift::stop(IOService *provider) {
    IOLog("VoltageShift: Stopping...\n");

    super::stop(provider);
}

uint64_t VoltageShift::a_rdmsr(uint32_t msr) {
#if TARGET_CPU_ARM64
    return (0);
#elif TARGET_CPU_X86_64
    return (rdmsr64(msr));
#endif /* TARGET_CPU_ARM64 */
}

void VoltageShift::a_wrmsr(uint32_t msr, uint64_t value) {
#if TARGET_CPU_ARM64
    return;
#elif TARGET_CPU_X86_64
    wrmsr64(msr, value);
#endif /* TARGET_CPU_ARM64 */
}

IOReturn VoltageShift::runAction(UInt32 action, UInt32 *outSize, void **outData, void *extraArg) {
#ifdef DEBUG
    IOLog("Action: %x", (unsigned int)action);
#endif /* DEBUG */

    return kIOReturnSuccess;
}

IOReturn VoltageShift::newUserClient(task_t owningTask, void *securityID, UInt32 type, IOUserClient **handler) {
#if TARGET_CPU_ARM64
    IOLog("VoltageShift: is not supported for Apple Silicon (ARM64)\n");
    return (kIOReturnError);
#endif /* TARGET_CPU_ARM64 */

    IOReturn ioReturn = kIOReturnSuccess;
    /* Only root user can access MSRs */
    // if (IOUserClient::clientHasPrivilege(owningTask, kIOClientPrivilegeAdministrator) != kIOReturnSuccess) {
    //     IOLog("VoltageShift: Only root user is allowed to create user client\n");
    //     return(kIOReturnNotPrivileged);
    // }

    AnVMSRUserClient *client = NULL;

    if (mClientCount > MAXUSERS) {
        IOLog("VoltageShift: Client already created, not deleted\n");
        return (kIOReturnError);
    }

    client = (AnVMSRUserClient *)AnVMSRUserClient::withTask(owningTask);

    if (client == NULL) {
        ioReturn = kIOReturnNoResources;
        IOLog("VoltageShift::newUserClient: Can't create user client\n");
    }
    /* Start the client so it can accept requests. */
    if (ioReturn == kIOReturnSuccess) {
        client->attach(this);
        if (client->start(this) == false) {
            ioReturn = kIOReturnError;
            IOLog("VoltageShift::newUserClient: Can't start user client\n");
        }
    }

    if (ioReturn != kIOReturnSuccess && client != NULL) {
        IOLog("VoltageShift: newUserClient error\n");
        client->detach(this);
        client->release();
    }
    else {
        mClientPtr[mClientCount] = client;

        *handler = client;

        client->set_Q_Size(type);
        mClientCount++;
    }

#ifdef DEBUG
    IOLog("VoltageShift: newUserClient() client = %p\n", mClientPtr[mClientCount]);
#endif /* DEBUG */

    return (ioReturn);
}

void VoltageShift::setErr(bool set) {
    mErrFlag = set;
}

void VoltageShift::closeChild(AnVMSRUserClient *ptr) {
    UInt8 i, idx;
    idx = 0;

    if (mClientCount == 0) {
        IOLog("No clients available to close");
        return;
    }

#ifdef DEBUG
    IOLog("Closing: %p\n", ptr);

    for (i = 0; i < mClientCount; i++) {
        IOLog("userclient ref: %d %p\n", i, mClientPtr[i]);
    }
#endif /* DEBUG */

    for (i = 0; i < mClientCount; i++) {
        if (mClientPtr[i] == ptr) {
            mClientCount--;
            mClientPtr[i] = NULL;
            idx = i;
            i = mClientCount + 1;
        }
    }

    for (i = idx; i < mClientCount; i++) {
        mClientPtr[i] = mClientPtr[i + 1];
    }
    mClientPtr[mClientCount + 1] = NULL;
}

#undef super

#define super IOUserClient

OSDefineMetaClassAndStructors(AnVMSRUserClient, IOUserClient);

const AnVMSRUserClient *AnVMSRUserClient::withTask(task_t owningTask) {
    AnVMSRUserClient *client;
    client = new AnVMSRUserClient;

    if (client != NULL) {
        if (client->init() == false) {
            client->release();
            client = NULL;
        }
    }
    if (client != NULL) {
        client->fTask = owningTask;
    }

    return (client);
}

bool AnVMSRUserClient::set_Q_Size(UInt32 capacity) {
    if (capacity == 0) {
        return true;
    }

#ifdef DEBUG
    IOLog("AnVMSR: Reseting size of data queue, all data in queue is lost");
#endif /* DEBUG */
    /* Get mem for new queue of calculated size */
    return true;
}

void AnVMSRUserClient::messageHandler(UInt32 type, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

bool AnVMSRUserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type, OSDictionary *properties) {
    return super::initWithTask(owningTask, securityID, type, properties);
}

bool AnVMSRUserClient::start(IOService *provider) {
    if (!super::start(provider))
        return false;

    mDevice = OSDynamicCast(VoltageShift, provider);
    mDevice->retain();

    return true;
}

bool AnVMSRUserClient::willTerminate(IOService *provider, IOOptionBits options) {
    return super::willTerminate(provider, options);
}

bool AnVMSRUserClient::didTerminate(IOService *provider, IOOptionBits options, bool *defer) {
    /* if defer is true, stop will not be called on the user client */
    *defer = false;

    return super::didTerminate(provider, options, defer);
}

bool AnVMSRUserClient::terminate(IOOptionBits options) {
    return super::terminate(options);
}

/* clientClose is called when the user process calls IOServiceClose */
IOReturn AnVMSRUserClient::clientClose() {
    if (mDevice != NULL) {
        mDevice->closeChild(this);
    }

    if (!isInactive())
        terminate();

    return kIOReturnSuccess;
}

/* clientDied is called when the user process terminates unexpectedly, the default implementation simply calls clientClose */
IOReturn AnVMSRUserClient::clientDied() {
    return clientClose();
}

void AnVMSRUserClient::free(void) {
    mDevice->release();

    super::free();
}

/* stop will be called during the termination process, and should free all resources associated with this client */
void AnVMSRUserClient::stop(IOService *provider) {
    super::stop(provider);
}

/* getTargetAndMethodForIndex looks up the external methods - supply a description of the parameters, available to be called */
IOExternalMethod *AnVMSRUserClient::getTargetAndMethodForIndex(IOService **target, UInt32 index) {
    static const IOExternalMethod methodDescs[4] = {
        { NULL, (IOMethod) &AnVMSRUserClient::actionMethodRDMSR, kIOUCStructIStructO, kIOUCVariableStructureSize, kIOUCVariableStructureSize },
        { NULL, (IOMethod) &AnVMSRUserClient::actionMethodWRMSR, kIOUCStructIStructO, kIOUCVariableStructureSize, kIOUCVariableStructureSize },
        { NULL, (IOMethod) &AnVMSRUserClient::actionMethodPrepareMap, kIOUCStructIStructO, kIOUCVariableStructureSize, kIOUCVariableStructureSize },
    };

    *target = this;

    if (index < 4)
        return (IOExternalMethod *) (methodDescs + index);

    return NULL;
}

IOReturn AnVMSRUserClient::actionMethodRDMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize) {
    inout *msrdata = (inout *)dataIn;
    inout *msroutdata = (inout *)dataOut;

#ifdef DEBUG
    IOLog("AnVMSR RDMSR called\n");
#endif /* DEBUG */

    if (!dataIn) {
        return kIOReturnUnsupported;
    }

    msrdata->param = mDevice->a_rdmsr(msrdata->msr);

#ifdef DEBUG
    IOLog("AnVMSR: RDMSR %X : 0x%llX\n", msrdata->msr, msrdata->param);
#endif /* DEBUG */

    if (!dataOut) {
        return kIOReturnUnsupported;
    }

    msroutdata->param = msrdata->param;

    return kIOReturnSuccess;
}

IOReturn AnVMSRUserClient::actionMethodWRMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize) {
    inout *msrdata = (inout *)dataIn;

#ifdef DEBUG
    IOLog("VoltageShift WRMSR called\n");
#endif /* DEBUG */

    if (!dataIn) {
        return kIOReturnUnsupported;
    }

    mDevice->a_wrmsr(msrdata->msr, msrdata->param);

#ifdef DEBUG
    IOLog("VoltageShift: WRMSR 0x%llX to %X\n", msrdata->param, msrdata->msr);
#endif /* DEBUG */

    return kIOReturnSuccess;
}

IOReturn AnVMSRUserClient::actionMethodPrepareMap(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize, IOByteCount *outputSize) {
    map_t *mapdata = (map_t *)dataIn;
    map_t *mapoutdata = (map_t *)dataOut;

#ifdef  DEBUG
    IOLog("VoltageShift PrepareMap called\n");
#endif /* DEBUG */

    if (!dataIn) {
        return kIOReturnUnsupported;
    }

    if (LastMapAddr || LastMapSize)
        return kIOReturnNotOpen;

    LastMapAddr = mapdata->addr;
    LastMapSize = mapdata->size;

#ifdef  DEBUG
    IOLog("VoltageShift: PrepareMap 0x%08llx[0x%llx]\n", LastMapAddr, LastMapSize);
#endif /* DEBUG */

    *outputSize = sizeof(map_t);

    return kIOReturnSuccess;
}

IOReturn AnVMSRUserClient::clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) {
    IOMemoryDescriptor *memDesc;

#ifdef DEBUG
    IOLog("VoltageShift: clientMemoryForType(%x, %p, %p)\n", type, options, memory);
#endif /* DEBUG */

    if (type != 0) {
        IOLog("VoltageShift: Unknown mapping type %x.\n", (unsigned int)type);
        return kIOReturnUnsupported;
    }

    if ((LastMapAddr == 0) && (LastMapSize == 0)) {
        IOLog("VoltageShift: No PrepareMap called.\n");
        return kIOReturnNotAttached;
    }

#ifdef DEBUG
    IOLog("VoltageShift: Mapping physical 0x%08llx[0x%llx]\n", LastMapAddr, LastMapSize);
#endif /* DEBUG */

    memDesc = IOMemoryDescriptor::withPhysicalAddress(LastMapAddr, LastMapSize, kIODirectionIn);
    /* Reset mapping to zero */
    LastMapAddr = 0;
    LastMapSize = 0;

    if (memDesc == 0) {
        IOLog("VoltageShift: Could not map memory!\n");
        return kIOReturnNotOpen;
    }

    memDesc->retain();
    *memory = memDesc;

#ifdef DEBUG
    IOLog("VoltageShift: Mapping succeeded.\n");
#endif /* DEBUG */

    return kIOReturnSuccess;
}
