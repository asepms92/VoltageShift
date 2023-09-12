// This is modified version of AnVMSR for MSR acress

#include "VoltageShiftAnVMSR.h"

#define super IOService

OSDefineMetaClassAndStructors (VoltageShiftAnVMSR, IOService)

bool VoltageShiftAnVMSR::init (OSDictionary *dict)
{
    bool res = super::init (dict);

#ifdef DEBUG
    IOLog ("VoltageShiftAnVMSR: Initializing...\n");
#endif // DEBUG

    return(res);
}

void VoltageShiftAnVMSR::free ()
{
#ifdef DEBUG
    IOLog ("VoltageShiftAnVMSR: Freeing...\n");
#endif // DEBUG

    super::free ();
}

bool VoltageShiftAnVMSR::start (IOService *provider)
{
    bool res = super::start (provider);

    registerService();
    IOLog ("VoltageShiftAnVMSR: Starting...\n");

    mPrefPanelMemoryBufSize = 4096;

    return(res);
}

void VoltageShiftAnVMSR::stop (IOService *provider)
{
    IOLog ("AnVMSR: Stopping...\n");

    super::stop (provider);
}

uint64_t VoltageShiftAnVMSR::a_rdmsr (uint32_t msr)
{
#if TARGET_CPU_ARM64
    return(0);
#elif TARGET_CPU_X86_64
    return(rdmsr64(msr));
#endif // TARGET_CPU_ARM64
}

void VoltageShiftAnVMSR::a_wrmsr(uint32_t msr, uint64_t value)
{
#if TARGET_CPU_ARM64
    return;
#elif TARGET_CPU_X86_64
    wrmsr64(msr, value);
#endif // TARGET_CPU_ARM64
}

IOReturn VoltageShiftAnVMSR::runAction(UInt32 action, UInt32 *outSize, void **outData, void *extraArg)
{
#ifdef DEBUG
    IOLog("Action: %x", (unsigned int)action);
#endif // DEBUG

    return kIOReturnSuccess;
}

IOReturn VoltageShiftAnVMSR::newUserClient( task_t owningTask, void * securityID, UInt32 type, IOUserClient ** handler )
{
#if TARGET_CPU_ARM64
    IOLog("VoltageShiftAnVMSR: is not support Apple Silicon (ARM64)\n");
    return(kIOReturnError);
#endif // TARGET_CPU_ARM64

    IOReturn ioReturn = kIOReturnSuccess;

    AnVMSRUserClient *client = NULL;

    if (mClientCount > MAXUSERS) {
        IOLog("VoltageShiftAnVMSR: Client already created, not deleted\n");
        return(kIOReturnError);
    }

    client = (AnVMSRUserClient *)AnVMSRUserClient::withTask(owningTask);

    if (client == NULL) {
        ioReturn = kIOReturnNoResources;
        IOLog("VoltageShiftAnVMSR::newUserClient: Can't create user client\n");
    }

    if (ioReturn == kIOReturnSuccess) {
        // Start the client so it can accept requests.
        client->attach(this);
        if (client->start(this) == false) {
            ioReturn = kIOReturnError;
            IOLog("VoltageShiftAnVMSR::newUserClient: Can't start user client\n");
        }
    }

    if (ioReturn != kIOReturnSuccess && client != NULL) {
        IOLog("VoltageShiftAnVMSR: newUserClient error\n");
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
    IOLog("VoltageShiftAnVMSR: newUserClient() client = %p\n", mClientPtr[mClientCount]);
#endif // DEBUG

    return (ioReturn);
}

void VoltageShiftAnVMSR::setErr( bool set )
{
    mErrFlag = set;
}

void VoltageShiftAnVMSR::closeChild(AnVMSRUserClient *ptr)
{
    UInt8 i, idx;
    idx = 0;

    if (mClientCount == 0) {
        IOLog("No clients available to close");
        return;
    }

#ifdef DEBUG
    IOLog("Closing: %p\n",ptr);

    for (i=0;i<mClientCount;i++) {
        IOLog("userclient ref: %d %p\n", i, mClientPtr[i]);
    }
#endif // DEBUG

    for (i=0;i<mClientCount;i++) {
        if (mClientPtr[i] == ptr) {
            mClientCount--;
            mClientPtr[i] = NULL;
            idx = i;
            i = mClientCount+1;
        }
    }

    for (i=idx;i<mClientCount;i++) {
        mClientPtr[i] = mClientPtr[i+1];
    }
    mClientPtr[mClientCount+1] = NULL;
}

#undef super

#define super IOUserClient

OSDefineMetaClassAndStructors(AnVMSRUserClient, IOUserClient);

const AnVMSRUserClient *AnVMSRUserClient::withTask(task_t owningTask)
{
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

bool AnVMSRUserClient::set_Q_Size(UInt32 capacity)
{
    if (capacity == 0) {
        return true;
    }

#ifdef DEBUG
    IOLog("AnVMSR: Reseting size of data queue, all data in queue is lost");
#endif // DEBUG
    //Get mem for new queue of calcuated size
    return true;
}

void AnVMSRUserClient::messageHandler(UInt32 type, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

bool AnVMSRUserClient::initWithTask(task_t owningTask, void *securityID, UInt32 type,
                                       OSDictionary *properties)
{
    return super::initWithTask(owningTask, securityID, type, properties);
}

bool AnVMSRUserClient::start(IOService *provider)
{
    if (!super::start(provider))
        return false;

    mDevice = OSDynamicCast(VoltageShiftAnVMSR, provider);
    mDevice->retain();

    return true;
}

bool AnVMSRUserClient::willTerminate(IOService *provider, IOOptionBits options)
{
    return super::willTerminate(provider, options);
}

bool AnVMSRUserClient::didTerminate(IOService *provider, IOOptionBits options, bool *defer)
{
    // if defer is true, stop will not be called on the user client
    *defer = false;

    return super::didTerminate(provider, options, defer);
}

bool AnVMSRUserClient::terminate(IOOptionBits options)
{
    return super::terminate(options);
}

// clientClose is called when the user process calls IOServiceClose
IOReturn AnVMSRUserClient::clientClose()
{
    if (mDevice != NULL) {
        mDevice->closeChild(this);
    }

    if (!isInactive())
        terminate();

    return kIOReturnSuccess;
}

// clientDied is called when the user process terminates unexpectedly, the default implementation simply calls clientClose
IOReturn AnVMSRUserClient::clientDied()
{
    return clientClose();
}

void AnVMSRUserClient::free(void)
{
    mDevice->release();

    super::free();
}

// stop will be called during the termination process, and should free all resources associated with this client
void AnVMSRUserClient::stop(IOService *provider)
{
    super::stop(provider);
}

// getTargetAndMethodForIndex looks up the external methods - supply a description of the parameters, available to be called
IOExternalMethod * AnVMSRUserClient::getTargetAndMethodForIndex(IOService **target, UInt32 index)
{
    static const IOExternalMethod methodDescs[3] = {
        { NULL, (IOMethod) &AnVMSRUserClient::actionMethodRDMSR, kIOUCStructIStructO, kIOUCVariableStructureSize, kIOUCVariableStructureSize },
        { NULL, (IOMethod) &AnVMSRUserClient::actionMethodWRMSR, kIOUCStructIStructO, kIOUCVariableStructureSize, kIOUCVariableStructureSize },
    };

    *target = this;
    if (index < 3)
        return (IOExternalMethod *) (methodDescs + index);

    return NULL;
}

IOReturn AnVMSRUserClient::actionMethodRDMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize,
                                           IOByteCount *outputSize)
{
    inout * msrdata = (inout *)dataIn;
    inout * msroutdata = (inout *)dataOut;

#ifdef DEBUG
    IOLog("AnVMSR RDMSR called\n");
#endif // DEBUG

    if (!dataIn) {
        return kIOReturnUnsupported;
    }
    msrdata->param = mDevice->a_rdmsr(msrdata->msr);

#ifdef DEBUG
    IOLog("AnVMSR: RDMSR %X : 0x%llX\n", msrdata->msr, msrdata->param);
#endif // DEBUG

    if (!dataOut) {
        return kIOReturnUnsupported;
    }
    msroutdata->param = msrdata->param;

    return kIOReturnSuccess;
}

IOReturn AnVMSRUserClient::actionMethodWRMSR(UInt32 *dataIn, UInt32 *dataOut, IOByteCount inputSize,
                                             IOByteCount *outputSize)
{
    inout * msrdata = (inout *)dataIn;

#ifdef DEBUG
    IOLog("VoltageShiftAnVMSR WRMSR called\n");
#endif // DEBUG

    if (!dataIn) {
        return kIOReturnUnsupported;
    }

    mDevice->a_wrmsr(msrdata->msr, msrdata->param);

#ifdef DEBUG
    IOLog("VoltageShiftAnVMSR: WRMSR 0x%llX to %X\n", msrdata->param, msrdata->msr);
#endif // DEBUG

    return kIOReturnSuccess;
}

IOReturn AnVMSRUserClient::clientMemoryForType(UInt32 type, IOOptionBits *options,
                                                  IOMemoryDescriptor **memory)
{
    IOBufferMemoryDescriptor *memDesc;
    char *msgBuffer;

    *options = 0;
    *memory = NULL;

    memDesc = IOBufferMemoryDescriptor::withOptions(kIOMemoryKernelUserShared, mDevice->mPrefPanelMemoryBufSize);

    if (!memDesc) {
        return kIOReturnUnsupported;
    }

    msgBuffer = (char *) memDesc->getBytesNoCopy();
    bcopy(mDevice->mPrefPanelMemoryBuf, msgBuffer, mDevice->mPrefPanelMemoryBufSize);
    *memory = memDesc; // automatically released after memory is mapped into task

    return(kIOReturnSuccess);
}
