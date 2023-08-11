/*
 * Copyright (C) 2016 The Android Open Source Project
 * Copyright (C) 2016 The CyanogenMod Project
 * Copyright (C) 2016 The Mokee Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you
 *  may not use this file except in compliance with the License.  You may
 *  obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 *  implied.  See the License for the specific language governing
 *  permissions and limitations under the License.
 */
#ifndef __FINGERPRINT_TZ_H_
#define __FINGERPRINT_TZ_H_

#include "fingerprint_common.h"
#include "MobiCoreDriverApi.h"

/* CMD */
typedef enum trust_zone_cmd_id_t {
    vfmProvision = 0x1,
    vfmInitialize = 0x2,
    vfmUninitialize = 0x3,
    vfmDeviceInitialize = 0x4,
    vfmDeviceCalibrate = 0x5,
    vfmAuthSessionBegin = 0x6,
    vfmAuthSessionEnd = 0x7,
    vfmCaptureStart = 0x8,
    vfmCaptureReadData = 0x9,
    vfmCaptureProcessData = 0xa,
    vfmCaptureAbort = 0xb,
    vfmCaptureGetStatus = 0xc,
    /* CMD id 0xd is unused. */
    vfmCaptureFlushImage = 0xe,
    vfmEnrollBegin = 0xf,
    vfmEnrollAddImage = 0x10,
    vfmEnrollFinish = 0x11,
    vfmEnrollmentPasswordSet = 0x12,
    vfmEnrollmentPasswordVerify = 0x13,
    vfmMatchImageToTemplates = 0x14,
    vfmPayloadBind = 0x15,
    vfmPayloadRelease = 0x16,
    vfmVendorDefinedOperation = 0x17,
    vfmGetSpiMode = 0x18,

    /* Response versions have the most significant bit set */
    vfmProvisionRsp = 0x80000001,
    vfmInitializeRsp = 0x80000002,
    vfmUninitializeRsp = 0x80000003,
    vfmDeviceInitializeRsp = 0x80000004,
    vfmDeviceCalibrateRsp = 0x80000005,
    vfmAuthSessionBeginRsp = 0x80000006,
    vfmAuthSessionEndRsp = 0x80000007,
    vfmCaptureStartRsp = 0x80000008,
    vfmCaptureReadDataRsp = 0x80000009,
    vfmCaptureProcessDataRsp = 0x8000000a,
    vfmCaptureAbortRsp = 0x8000000b,
    vfmCaptureGetStatusRsp = 0x8000000c,
    /* CMD id 0xd is unused. */
    vfmCaptureFlushImageRsp = 0x8000000e,
    vfmEnrollBeginRsp = 0x8000000f,
    vfmEnrollAddImageRsp = 0x80000010,
    vfmEnrollFinishRsp = 0x80000011,
    vfmEnrollmentPasswordSetRsp = 0x80000012,
    vfmEnrollmentPasswordVerifyRsp = 0x80000013,
    vfmMatchImageToTemplatesRsp = 0x80000014,
    vfmPayloadBindRsp = 0x80000015,
    vfmPayloadReleaseRsp = 0x80000016,
    vfmVendorDefinedOperationRsp = 0x80000017,
    vfmGetSpiModeRsp = 0x80000018
}trust_zone_cmd_id_t;

typedef enum trust_zone_vendor_cmd_id_t {
    vendorUnknown0 = 0x0,
    vendorGetVersion = 0x1,//0x10
    vendorUnknownA = 0xa,
    vendorGetAuthToken = 0x14,
    vendorEnterAuthSession = 0x15,
    vendorUpdateCalData = 0x17
}trust_zone_vendor_cmd_id_t;

typedef struct {
    uint32_t len;
    uint32_t addr;
} ioData;

typedef struct {
    trust_zone_cmd_id_t cmd;
    uint32_t unk_8000;
    uint32_t enroll_fp_idx;
    uint32_t templates_len;
    uint32_t unknown2;
    trust_zone_vendor_cmd_id_t vendor_cmd;
    ioData input;
    ioData cmd_custom[30];
    uint32_t ion_phys_addr;
    trust_zone_cmd_id_t return_cmd;
    uint32_t return_code;
    ioData output;
    ioData ext_output;
} tciMessageS5;

typedef struct {
    uint8_t* input_buf;
    uint32_t input_addr;
    uint32_t input_len;
    mcBulkMap_t input_map;
    uint8_t* output_buf;
    uint32_t output_addr;
    uint32_t output_len;
    mcBulkMap_t output_map;
} g_addrs_struct;

//for ioctl
typedef struct secfd_info_t {
     int fd_ion_handle;
     uint32_t ion_phys_addr;
} secfd_info_t;

typedef struct trust_zone_t {
    bool init;
    worker_state_t state;
    g_addrs_struct g_addrs;
    g_addrs_struct g_ext_addrs;
    uint8_t* drv_wsm;
    tciMessageS5* fp_wsm;
    mcSessionHandle_t dr_session;
    mcSessionHandle_t ta_session;
    bool auth_session_opend;
    char auth_token[AUTH_TOKEN_LENGTH];
    char auth_session_token[AUTH_SESSION_TOKEN_LENGTH];
    int calibrate_len;
    char calibrate_data[CALIBRATE_DATA_MAX_LENGTH];
    finger_t finger[MAX_NUM_FINGERS + 1]; // Start from finger[1]
    timeout_t timeout;
    pthread_t auth_thread;
    pthread_t enroll_thread;
    pthread_mutex_t lock;
    int fd_crypt_mem;
    int fd_ion;
    secfd_info_t secfd_info;
    uint8_t* ion_buf;
}trust_zone_t;

#define FINGERPRINT_ERROR_HW_UNAVAILABLE (1)
#define FINGERPRINT_ERROR_UNABLE_TO_PROCESS (2)
#define FINGERPRINT_ERROR_TIMEOUT (3)
#define FINGERPRINT_ERROR_NO_SPACE (4)
#define FINGERPRINT_ERROR_CANCELED (5)
#define FINGERPRINT_ERROR_UNABLE_TO_REMOVE (6)
#define FINGERPRINT_ERROR_VENDOR_BASE (1000)

worker_state_t get_tz_state();
void set_tz_state(worker_state_t state);

int vcs_update_cal_data();
int vcs_check_state();
int vcs_start_capture();
void* vcs_authenticate(void* vdev);
void* vcs_enroll(void* vdev);
int vcs_start_authenticate(void *vdev);
int vcs_start_enroll(void *vdev, uint32_t timeout);
int vcs_get_enrolled_finger_num();
int vcs_update_auth_token();
int vcs_start_auth_session();
int vcs_stop_auth_session();
int vcs_resume();
int vcs_uninit();
int vcs_init();

#endif /* __FINGERPRINT_TZ_H_ */
