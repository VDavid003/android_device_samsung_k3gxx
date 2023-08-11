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

#define LOG_TAG "Fingerprint_tz"
#define LOG_NDEBUG 1

#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <cutils/log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "fingerprint_tz.h"
#include "fp_k3gxx.h"
#include "ion/ion.h"

extern vcs_sensor_t sensor;
trust_zone_t tz;

worker_state_t get_tz_state() {
    worker_state_t state;

    pthread_mutex_lock(&tz.lock);
    state = tz.state;
    pthread_mutex_unlock(&tz.lock);

    return state;
}

void set_tz_state(worker_state_t state) {
    pthread_mutex_lock(&tz.lock);
    tz.state = state;
    pthread_mutex_unlock(&tz.lock);
}

/*
 * cmd: vendorUpdateCalData
 */
int vcs_update_cal_data() {
    tz.fp_wsm->cmd = vfmVendorDefinedOperation;
    tz.fp_wsm->vendor_cmd = vendorUpdateCalData;
    tz.fp_wsm->input.addr = 0;
    tz.fp_wsm->input.len = 0;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    tz.fp_wsm->output.len = CALIBRATE_DATA_MAX_LENGTH;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
        ALOGE("Update Cal Data error");
        return -1;
    }

    tz.calibrate_len = ((uint32_t*)tz.g_addrs.output_buf)[1] + 0xf;
    memcpy(&tz.calibrate_data, tz.g_addrs.output_buf, tz.calibrate_len);
    ALOGV("Sended vendorUpdateCalData");
    return 0;
}

int vcs_check_state() {
    if (get_tz_state() == STATE_IDLE)
        return 1;
    if (get_tz_state() == STATE_CANCEL) {
        tz.fp_wsm->cmd = vfmCaptureAbort;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        set_tz_state(STATE_IDLE);
        return 1;
    }
    return 0;
}

/*
 * cmd: 1.vfmCaptureStart
 *      2.vfmCaptureReadData * N
 *      3.vfmCaptureProcessData
 */
int vcs_start_capture(void *vdev, time_t t) {
    tz.fp_wsm->cmd = vfmCaptureStart;
    tz.fp_wsm->input.len = 0x1c;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    memset(tz.g_addrs.input_buf, 0, 0x1c);
    tz.g_addrs.input_buf[16] = 0x1;
    if (t) {
        *(time_t*)(&tz.g_addrs.input_buf[20]) = t;
    }
    tz.g_addrs.input_buf[24] = 0xc0;
    tz.g_addrs.input_buf[25] = 0x12;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if ((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmCaptureStartRsp)) {
        ALOGE("Send vfmCaptureStart error");
        return -1;
    }

    vcs_update_cal_data();
    pthread_mutex_lock(&sensor.lock);
    sensor_capture_start();
    pthread_mutex_unlock(&sensor.lock);

    pthread_mutex_lock(&sensor.lock);
    while ((!vcs_check_state()) && !sensor.signal) {
        pthread_cond_wait(&sensor.cond, &sensor.lock);
    }
    pthread_mutex_unlock(&sensor.lock);
    if (vcs_check_state()) {
        return -1;
    }
    pthread_mutex_lock(&sensor.lock);
    if (sensor.signal == true) {
        sensor.signal = false;
    }
    pthread_mutex_unlock(&sensor.lock);

    while(1) {
        if (vcs_check_state()) {
            return -1;
        }
        tz.fp_wsm->cmd = vfmCaptureReadData;
        tz.fp_wsm->unk_8000 = 0x8000;
        tz.fp_wsm->output.len = 0xc;
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        if ((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmCaptureReadDataRsp)) {
            ALOGE("Send vfmCaptureReadData error");
            continue;
        }
        if (tz.g_addrs.output_buf[0] == 2) {
            ALOGV("User's finger removed from sensor");
            break;
        }
        //usleep(200000);
    }
    tz.fp_wsm->cmd = vfmCaptureProcessData;
    tz.fp_wsm->input.len = 0x1c;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    memset(tz.g_addrs.input_buf, 0, 0x1c);
    tz.g_addrs.input_buf[16] = 0x1;
    *(time_t*)(&tz.g_addrs.input_buf[20]) = time(NULL);
    tz.g_addrs.input_buf[24] = 0xc0;
    tz.g_addrs.input_buf[25] = 0x12;
    tz.fp_wsm->output.len = 0xc;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if (tz.fp_wsm->return_cmd != vfmCaptureProcessDataRsp) {
        ALOGE("Send vfmCaptureProcessData error");
        return -1;
    }
    if (tz.fp_wsm->return_code != 0) {
        ALOGE("resp->result=%d",tz.fp_wsm->return_code);
        send_acquired_notice(vdev, tz.fp_wsm->return_code);
        return vcs_start_capture(vdev, time(NULL));
    }
    return 0;
}

/*
 * cmd: 1.vendorUnknown0
 *      2.vcs_start_capture
 *      3.vfmMatchImageToTemplates
 *      4.vfmPayloadRelease
 */

void* vcs_authenticate(void* vdev) {
    int ret = 0;
    int fingerindex = 0;
    int len = 0;
    int fake_fid = 0;

    tz.fp_wsm->cmd = vfmVendorDefinedOperation;
    tz.fp_wsm->vendor_cmd = vendorUnknown0;
    tz.fp_wsm->input.addr = 0;
    tz.fp_wsm->input.len = 0;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    tz.fp_wsm->output.len = 0x4;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
        ALOGE("%s:Send vendor unknown 0 cmd error", __FUNCTION__);
    }

    while (get_tz_state() == STATE_SCAN) {
        ret = vcs_start_capture(vdev, 0);
        if (ret == -1)
            goto out;
        tz.fp_wsm->cmd = vfmMatchImageToTemplates;
        tz.fp_wsm->input.len = 0x14;
        tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
        memset(tz.g_addrs.input_buf, 0, 0x14);
        ((uint32_t*)(tz.g_addrs.input_buf))[0] = 1;
        ((uint32_t*)(tz.g_addrs.input_buf))[1] = 100000;
        ((uint32_t*)(tz.g_addrs.input_buf))[2] = time(NULL);
        ((uint32_t*)(tz.g_addrs.input_buf))[3] = 0x1;
        tz.fp_wsm->templates_len = vcs_get_enrolled_finger_num();

        len = 0;
        for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++)
            if (tz.finger[idx].exist) {
                tz.fp_wsm->cmd_custom[len].len = FINGER_DATA_MAX_LENGTH;
                tz.fp_wsm->cmd_custom[len].addr = tz.g_ext_addrs.input_addr + (len * FINGER_DATA_MAX_LENGTH);
                memcpy(&tz.g_ext_addrs.input_buf[(len * FINGER_DATA_MAX_LENGTH)], &tz.finger[idx].data, FINGER_DATA_MAX_LENGTH);
                len++;
            }
        tz.fp_wsm->output.len = 0x5c;
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        tz.fp_wsm->ext_output.len = 0x3000;
        tz.fp_wsm->ext_output.addr = tz.g_ext_addrs.output_addr;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        if (tz.fp_wsm->return_cmd != vfmMatchImageToTemplatesRsp) {
            ALOGE("%s:send vfmMatchImageToTemplates error", __FUNCTION__);
            send_error_notice(vdev, FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
            goto out;
        }
        if (tz.fp_wsm->return_code != 0) {
            send_acquired_notice(vdev, tz.fp_wsm->return_code);
            continue;
        }
        fake_fid = (int)tz.g_addrs.output_buf[80]+1;
        len = 0;
        for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++) {
            if (tz.finger[idx].exist) {
                len++;
                if (len == fake_fid) {
                    fingerindex = idx;
                    break;
                }
            }
        }
        ALOGV("Auth fingerindex=%d", fingerindex);
        //memcpy(&tz.finger[fingerindex].data, &resp_2x->data[102419], FINGER_DATA_MAX_LENGTH);
        //db_write_to_db(vdev, false, fingerindex);

        tz.fp_wsm->cmd = vfmPayloadRelease;
        tz.fp_wsm->input.len = PAYLOAD_MAX_LENGTH;
        tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
        memcpy(tz.g_addrs.input_buf, &tz.finger[fingerindex].payload, PAYLOAD_MAX_LENGTH);
        tz.fp_wsm->output.len = 0x24;
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        break;
    }
out:
    sensor_uninit();
    vcs_uninit();
    set_tz_state(STATE_IDLE);
    if (fingerindex) {
        send_authenticated_notice(vdev, fingerindex);
    }
    return NULL;
}

/*
 * cmd: 1.vfmEnrollBegin
 *      2.vendorUnknownA
 *      3.vcs_start_capture * 8
 *      4.vfmEnrollAddImage
 *      5.vfmEnrollFinish
 *      6.vfmPayloadBind
 *      7.vfmEnrollmentPasswordSet
 */

void* vcs_enroll(void* vdev) {
    int count = 8;
    int ret = 0;
    int i = 0;

    int idx = 1;
    for (idx = 1; idx <= MAX_NUM_FINGERS; idx++) {
        if (!tz.finger[idx].exist) {
            break;
        }
    }

    tz.fp_wsm->cmd = vfmEnrollBegin;
    tz.fp_wsm->enroll_fp_idx = idx;
    tz.fp_wsm->input.addr = 0;
    tz.fp_wsm->input.len = 0;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmEnrollBeginRsp)) {
        ALOGE("send EnrollBegin error");
        set_tz_state(STATE_IDLE);
        send_error_notice(vdev, FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return NULL;
    }
    tz.fp_wsm->cmd = vfmVendorDefinedOperation;
    tz.fp_wsm->vendor_cmd = vendorUnknownA;
    tz.fp_wsm->input.addr = 0;
    tz.fp_wsm->input.len = 0;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    tz.fp_wsm->output.len = 0x4;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
        ALOGE("send vendorUnknownA error");
        set_tz_state(STATE_IDLE);
        send_error_notice(vdev, FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
        return NULL;
    }
    while (get_tz_state() == STATE_ENROLL) {
        ret = vcs_start_capture(vdev, 0);
        if (ret == -1)
            goto out;
        tz.fp_wsm->cmd = vfmEnrollAddImage;
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        tz.fp_wsm->output.len = 0x8;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        if (tz.fp_wsm->return_cmd != vfmEnrollAddImageRsp) {
            ALOGE("%s:send vfmEnrollAddImage error", __FUNCTION__);
            set_tz_state(STATE_IDLE);
            send_error_notice(vdev, FINGERPRINT_ERROR_UNABLE_TO_PROCESS);
            return NULL;
        }
        if (tz.fp_wsm->return_code != 0) {
            send_acquired_notice(vdev, tz.fp_wsm->return_code);
            continue;
        }
        count--;
        if (tz.g_addrs.output_buf[0] == 0x1)
            count = 0;
        if (tz.g_addrs.output_buf[0] != 0x1 && count == 0)
            count = 1;
        send_enroll_notice(vdev, idx, count);
        if (count == 0)
            break;
    }
    tz.fp_wsm->cmd = vfmEnrollFinish;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    tz.fp_wsm->input.len = AUTH_SESSION_TOKEN_LENGTH;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    tz.fp_wsm->output.len = FINGER_DATA_MAX_LENGTH;
    memcpy(tz.g_addrs.input_buf, &tz.auth_session_token, AUTH_SESSION_TOKEN_LENGTH);
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
        ALOGE("Send vfmEnrollFinish error");
    }
    memcpy(&tz.finger[idx].data, tz.g_addrs.output_buf, FINGER_DATA_MAX_LENGTH);
    for (i = 0; i < 2; i++) {
        tz.fp_wsm->cmd = vfmPayloadBind;
        tz.fp_wsm->unknown2 = 0x1;
        tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
        tz.fp_wsm->input.len = 0x7;
        sprintf(tz.g_addrs.input_buf, "User_0");
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        if (i == 0) {
            tz.fp_wsm->output.len = 0x70;
        }
        if (i == 1) {
            tz.fp_wsm->output.len = PAYLOAD_MAX_LENGTH;
        }
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    }
    if ((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmPayloadBindRsp)) {
        ALOGE("Send vfmPayloadBind error");
    }
    memcpy(&tz.finger[idx].payload, tz.g_addrs.output_buf, PAYLOAD_MAX_LENGTH);
    tz.finger[idx].exist = true;
    db_write_to_db(vdev, false, idx);

#if 0
    // We may not need to send vfmEnrollmentPasswordSet.
    for (i = 0; i < 2; i++) {
        trust_zone_3x_cmd_t *send_3x_cmd = NULL;
        send_3x_cmd = (trust_zone_3x_cmd_t *)handle->ion_sbuffer;
        resp = (trust_zone_normal_result_t *)(handle->ion_sbuffer + QSEECOM_ALIGN(sizeof(trust_zone_3x_cmd_t)));
        memset(send_3x_cmd, 0, QSEECOM_ALIGN(sizeof(*send_3x_cmd)) + QSEECOM_ALIGN(sizeof(*resp)));
        send_3x_cmd->cmd = vfmEnrollmentPasswordSet;
        send_3x_cmd->len = AUTH_SESSION_TOKEN_LENGTH;
        memcpy(&send_3x_cmd->data, &tz.auth_session_token, AUTH_SESSION_TOKEN_LENGTH);
        if (i == 0) {
            resp->data[0] = 0x90;
        } else {
            resp->data[0] = 0x80;
        }
        ret = QSEECom_send_cmd(handle, send_3x_cmd, QSEECOM_ALIGN(sizeof(*send_3x_cmd)), resp, QSEECOM_ALIGN(sizeof(*resp)));
    }
    if (ret || resp->result) {
        ALOGE("Send vfmEnrollmentPasswordSet error");
    }
#endif
out:
    set_tz_state(STATE_IDLE);
    sensor_uninit();
    vcs_uninit();
    return NULL;
}

void* vcs_timeout(void* vdev) {
    struct timeval now;
    struct timespec outtime;
    int ret = 0;

    pthread_mutex_lock(&tz.timeout.lock);
    gettimeofday(&now, NULL);
    outtime.tv_sec = now.tv_sec + tz.timeout.timeout;
    outtime.tv_nsec = now.tv_usec * 1000;
    ret = pthread_cond_timedwait(&tz.timeout.cond, &tz.timeout.lock, &outtime);
    pthread_mutex_unlock(&tz.timeout.lock);

    if (ret == ETIMEDOUT) {
        ALOGI("Enroll timeout! Exit!");
        int flag = 0;
        if (get_tz_state() != STATE_IDLE && get_tz_state() != STATE_CANCEL) {
            set_tz_state(STATE_CANCEL);
            ioctl(sensor.fd, VFSSPI_IOCTL_SET_DRDY_INT, &flag);
            while (1) {
                usleep(100000);
                if (get_tz_state() == STATE_IDLE)
                    break;
            }
        }
        send_error_notice(vdev, FINGERPRINT_ERROR_TIMEOUT);
    }
    return NULL;
}

int vcs_start_authenticate(void *vdev) {
    int times = 0;
    for (times = 0; times < 5; times++)
        if (get_tz_state() != STATE_IDLE) {
            ALOGE("%s:Sensor is busy!", __FUNCTION__);
            if (times < 4) {
                usleep(100000);
                continue;
            }
            return -1;
        }
    set_tz_state(STATE_SCAN);
    int ret = 0;

    sensor_init();

    ret = vcs_init();
    if (ret) return ret;
    ret = pthread_create(&tz.auth_thread, NULL, vcs_authenticate, vdev);
    if (ret) {
        ALOGE("Can't create authenticate thread!!");
    }
    return ret;
}

int vcs_start_enroll(void *vdev, uint32_t timeout) {
    if (get_tz_state() != STATE_IDLE) {
        ALOGE("%s:Sensor is busy!", __FUNCTION__);
        return -1;
    }
    set_tz_state(STATE_ENROLL);
    int ret = 0;

    sensor_init();

    ret = vcs_init();
    if (ret) {
        return ret;
    }
    ret = pthread_create(&tz.enroll_thread, NULL, vcs_enroll, vdev);
    if (ret) {
        ALOGE("Can't create enroll thread!!");
        return ret;
    }
    if (timeout) {
        tz.timeout.timeout = timeout;
        ret = pthread_create(&tz.timeout.timeout_thread, NULL, vcs_timeout, vdev);
        if (ret) {
            ALOGE("Can't create timeout thread!!");
        }
    }
    return ret;
}

int vcs_get_enrolled_finger_num() {
    int num = 0;
    int idx = 1;
    for (idx = 1; idx <= MAX_NUM_FINGERS; idx++)
        if (tz.finger[idx].exist)
            num++;
    ALOGV("%s: num=%d", __FUNCTION__, num);
    return num;
}

/*
 * cmd: vendorGetAuthToken
 */
int vcs_update_auth_token() {
    //SAMSUNG WEED, I have zero idea how this works
    //DO NOT UNDER ANY CIRCUMSTANCES TRY TO UNDERSTAND THIS OR TOUCH THIS, IT WORKS SO LEAVE IT ALONE
    for (int i = 0;i < 2; i++) {
        tz.fp_wsm->cmd = vfmVendorDefinedOperation;
        tz.fp_wsm->vendor_cmd = vendorGetAuthToken;
        tz.fp_wsm->output.len = 0x9c;
        if (i == 0)
          tz.fp_wsm->output.len = 0xa0;
        tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        if (tz.fp_wsm->output.len == 0x9c) {
            break;
        }
    }
    if ((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
        ALOGE("send vendorGetAuthToken failed, TA result=%d", tz.fp_wsm->return_code);
        return -1;
    }
    memcpy(&tz.auth_token, tz.g_addrs.output_buf, AUTH_TOKEN_LENGTH);
    ALOGV("Sended vendorGetAuthToken");
    return 0;
}

/*
 * cmd: vfmAuthSessionBegin
 */

int vcs_start_auth_session() {
    tz.fp_wsm->cmd = vfmAuthSessionBegin;
    tz.fp_wsm->output.len = 0x20;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmAuthSessionBeginRsp)) {
        ALOGE("send vfmAuthSessionBegin failed, TA result=%d", tz.fp_wsm->return_code);
        return -1;
    }
    memcpy(&tz.auth_session_token, tz.g_addrs.output_buf, AUTH_SESSION_TOKEN_LENGTH);
    tz.auth_session_opend = true;
    ALOGV("Sended vfmAuthSessionBegin");
    return 0;
}

/*
 * cmd: vfmAuthSessionEnd
 */

int vcs_stop_auth_session() {
    tz.fp_wsm->cmd = vfmAuthSessionEnd;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmAuthSessionEndRsp)) {
        ALOGE("send vfmAuthSessionEnd failed, TA result=%d", tz.fp_wsm->return_code);
    }
    memset(tz.auth_session_token, 0, AUTH_SESSION_TOKEN_LENGTH);
    tz.auth_session_opend = false;
    ALOGV("Sended vfmAuthSessionEnd");
    return 0;
}

/*
 * cmd: 1.vfmInitialize
 *      2.vendorEnterAuthSession
 *      3.vfmDeviceInitialize
 *      4.vfmDeviceCalibrate
 */

int vcs_resume() {
    tz.fp_wsm->cmd = vfmInitialize;
    tz.fp_wsm->input.len = 4;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    memset(tz.g_addrs.input_buf, 0, 4);
    //qcom sets something to 2 here, we don't seem to do it
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmInitializeRsp)) {
        ALOGE("send vfmInitialize failed, TA result=%d", tz.fp_wsm->return_code);
        return -1;
    }
    ALOGV("Sended vfmInitialize");

    if (tz.auth_session_opend) {
        tz.fp_wsm->cmd = vfmVendorDefinedOperation;
        tz.fp_wsm->vendor_cmd = vendorEnterAuthSession;
        tz.fp_wsm->input.len = 0x9c;
        tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
        memcpy(tz.g_addrs.input_buf, &tz.auth_token, 0x9c);
        mcNotify(&tz.ta_session);
        mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
        if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmVendorDefinedOperationRsp)) {
            ALOGE("send EnterAuthSession failed, TA result=%d", tz.fp_wsm->return_code);
            return -1;
        }
    }
    ALOGV("Sended EnterAuthSession");

    tz.fp_wsm->cmd = vfmDeviceInitialize;
    tz.fp_wsm->input.len = 0;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmDeviceInitializeRsp)) {
        ALOGE("send vfmDeviceInitialize failed, TA result=%d", tz.fp_wsm->return_code);
        return -1;
    }
    ALOGV("Sended vfmDeviceInitialize");

    tz.fp_wsm->cmd = vfmDeviceCalibrate;
    tz.fp_wsm->input.addr = tz.g_addrs.input_addr;
    tz.fp_wsm->output.addr = tz.g_addrs.output_addr;
    memset(tz.g_addrs.input_buf, 0, 0x10);
    tz.g_addrs.input_buf[0] = 0xc0;
    tz.g_addrs.input_buf[1] = 0x12;
    tz.fp_wsm->output.len = CALIBRATE_DATA_MAX_LENGTH;
    if (tz.calibrate_len) {
        tz.fp_wsm->input.len = tz.calibrate_len;
        memcpy(&tz.g_addrs.input_buf[4], &tz.calibrate_data, tz.calibrate_len);
    } else {
        tz.fp_wsm->input.len = 0x10;
    }
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);
    if((tz.fp_wsm->return_code != 0) || (tz.fp_wsm->return_cmd != vfmDeviceCalibrateRsp)) {
        ALOGE("send vfmDeviceCalibrate failed, TA result=%d", tz.fp_wsm->return_code);
        return -1;
    }
    if (tz.calibrate_len == 0) {
        tz.calibrate_len = ((uint32_t*)tz.g_addrs.output_buf)[1] + 0xf;
        memcpy(&tz.calibrate_data, tz.g_addrs.output_buf, tz.calibrate_len);
    }
    ALOGV("Sended vfmDeviceCalibrate");
    return 0;
}

/*
 * cmd: vfmUninitialize
 * set bandwidth to low and shutdown app
 */

int vcs_uninit() {
    if (tz.auth_session_opend) {
        vcs_update_auth_token();
    }

    tz.fp_wsm->cmd = vfmUninitialize;
    mcNotify(&tz.ta_session);
    mcWaitNotification(&tz.ta_session, MC_INFINITE_TIMEOUT);

    mcUnmap(&tz.ta_session, tz.g_addrs.input_buf, &tz.g_addrs.input_map);
    tz.g_addrs.input_len = 0;
    tz.g_addrs.input_addr = 0;
    free(tz.g_addrs.input_buf);

    mcUnmap(&tz.ta_session, tz.g_addrs.output_buf, &tz.g_addrs.output_map);
    tz.g_addrs.output_len = 0;
    tz.g_addrs.output_addr = 0;
    free(tz.g_addrs.output_buf);

    mcUnmap(&tz.ta_session, tz.g_ext_addrs.input_buf, &tz.g_ext_addrs.input_map);
    tz.g_ext_addrs.input_len = 0;
    tz.g_ext_addrs.input_addr = 0;
    free(tz.g_ext_addrs.input_buf);

    mcUnmap(&tz.ta_session, tz.g_ext_addrs.output_buf, &tz.g_ext_addrs.output_map);
    tz.g_ext_addrs.output_len = 0;
    tz.g_ext_addrs.output_addr = 0;
    free(tz.g_ext_addrs.output_buf);

    mcCloseSession(&tz.dr_session);
    mcCloseSession(&tz.ta_session);
    mcFreeWsm(MC_DEVICE_ID_DEFAULT, tz.drv_wsm);
    mcFreeWsm(MC_DEVICE_ID_DEFAULT, (uint8_t*)tz.fp_wsm);
    mcCloseDevice(MC_DEVICE_ID_DEFAULT);

    tz.init = false;
    set_tz_state(STATE_IDLE);
    ALOGV("Closed securefp TA");
    return 0;
}

/*
 * start app and set bandwidth to high
 * Call vcs_resume
 */

mcUuid_t dr_uuid = {
    0xff, 0xff, 0xff, 0xff, 0xd0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e };

mcUuid_t ta_uuid = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e };


int vcs_init() {
    int ret = 0;
    if (tz.init) {
        ALOGI("securefp TA is already running!");
        return ret;
    }

    if (mcOpenDevice(MC_DEVICE_ID_DEFAULT) != MC_DRV_OK) {
        ALOGE("Opening MobiCore device failed");
        return -1;
    }

    if (mcMallocWsm(MC_DEVICE_ID_DEFAULT, 0, 300, &tz.drv_wsm, 0) != MC_DRV_OK) {
        ALOGE("Allocating secure driver WSM failed");
        return -1;
    }

    if (mcMallocWsm(MC_DEVICE_ID_DEFAULT, 0, 300, (uint8_t**)&tz.fp_wsm, 0) != MC_DRV_OK) {
        ALOGE("Allocating TA WSM failed");
        return -1;
    }

    if (mcOpenSession(&tz.dr_session, &dr_uuid, tz.drv_wsm, 300) != MC_DRV_OK) {
        ALOGE("Loading secure driver failed");
        return -1;
    }

    if (mcOpenSession(&tz.ta_session, &ta_uuid, (uint8_t*)tz.fp_wsm, 300) != MC_DRV_OK) {
        ALOGE("Loading securefp app failed");
        return -1;
    }

    tz.g_addrs.input_len = 0x25800;
    tz.g_addrs.input_buf = malloc(0x25800);
    if (mcMap(&tz.ta_session, tz.g_addrs.input_buf, tz.g_addrs.input_len, &tz.g_addrs.input_map) != MC_DRV_OK) {
        ALOGE("Mapping input buffer failed");
        return -1;
    }
    tz.g_addrs.input_addr = (uint32_t)tz.g_addrs.input_map.sVirtualAddr;

    tz.g_addrs.output_len = 0x25800;
    tz.g_addrs.output_buf = malloc(0x25800);
    if (mcMap(&tz.ta_session, tz.g_addrs.output_buf, tz.g_addrs.output_len, &tz.g_addrs.output_map) != MC_DRV_OK) {
        ALOGE("Mapping output buffer failed");
        return -1;
    }
    tz.g_addrs.output_addr = (uint32_t)tz.g_addrs.output_map.sVirtualAddr;

    tz.g_ext_addrs.input_len = 0x96000;
    tz.g_ext_addrs.input_buf = malloc(0x96000);
    if (mcMap(&tz.ta_session, tz.g_ext_addrs.input_buf, tz.g_ext_addrs.input_len, &tz.g_ext_addrs.input_map) != MC_DRV_OK) {
        ALOGE("Mapping special input buffer failed");
        return -1;
    }
    tz.g_ext_addrs.input_addr = (uint32_t)tz.g_ext_addrs.input_map.sVirtualAddr;

    tz.g_ext_addrs.output_len = 0x25800;
    tz.g_ext_addrs.output_buf = malloc(0x25800);
    if (mcMap(&tz.ta_session, tz.g_ext_addrs.output_buf, tz.g_ext_addrs.output_len, &tz.g_ext_addrs.output_map) != MC_DRV_OK) {
        ALOGE("Mapping special output buffer failed");
        return -1;
    }
    tz.g_ext_addrs.output_addr = (uint32_t)tz.g_ext_addrs.output_map.sVirtualAddr;

    tz.fd_crypt_mem = open("/dev/s5p-smem", O_RDWR);
    tz.fd_ion = open("/dev/ion", O_RDWR);

    ion_alloc_fd(tz.fd_ion, 0x20000, 0, 0x10, 0x80000, &tz.secfd_info.fd_ion_handle);
    tz.ion_buf = mmap(0, 0x20000, 3, 1, tz.secfd_info.fd_ion_handle, 0);

    //ioctl get phy address magic
    ioctl(tz.fd_crypt_mem, 0xc0085308, &tz.secfd_info);
    tz.fp_wsm->ion_phys_addr = tz.secfd_info.ion_phys_addr;
    memset(tz.ion_buf, 0, 0x20000);

    tz.init = true;

    ALOGV("securefp TA init success!");
    ret = vcs_resume();
    return ret;
}
