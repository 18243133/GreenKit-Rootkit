/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that app can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_MichMich,
    0xf3ee1d30,0xc325,0x483d,0x88,0x5e,0x37,0x83,0x4a,0xff,0x5d,0x2d);
// {f3ee1d30-c325-483d-885e-37834aff5d2d}
