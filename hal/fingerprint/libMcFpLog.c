#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <android/log.h>

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

#include "fingerprint_tz.h"

uint8_t* fp_tci;
uint32_t fp_session;

uint32_t input_addr = 0;
uint32_t input_len;
void* input_buf;

uint32_t output_addr = 0;
uint32_t output_len;
void* output_buf;

uint32_t ext_input_addr = 0;
uint32_t ext_input_len;
void* ext_input_buf;

uint32_t ext_output_addr = 0;
uint32_t ext_output_len;
void* ext_output_buf;


static void hex_dump(uint8_t* buf, uint32_t len) {
	if (len == 0)
		return;
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "HEX DUMP:");

	int remaining = len;
	for (int i = 0; i < (len / 256) + 1; i++) {
		if (remaining == 0)
			break;

		int toPrint = (remaining < 256) ? remaining : 256;
		char* str = malloc(toPrint * 2 + 1); //two letters for each byte and zero byte end
		char onehex[3] = "";
		str[0] = '\0';

		for(int j=0; j < toPrint; j++) {
			snprintf(onehex, 3, "%02x", buf[(len - remaining) + j]);
			strcat(str, onehex);
		}
		__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "%s", str);
		remaining -= toPrint;
		free(str);
	}
}

static void try_decode_send(tciMessageS5* tci) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "INPUT_LEN: %08x, INPUT_ADDR: %08x", tci->input.len, tci->input.addr);
	switch (tci->cmd) {
		case vfmProvision:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PROVISION (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmInitialize:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "INITIALIZE (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmUninitialize:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "UNINITIALIZE (no input)");
			break;
		case vfmDeviceInitialize:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "DEVICE_INITIALIZE (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmDeviceCalibrate:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "DEVICE_CALIBRATE (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmAuthSessionBegin:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "AUTH_SESSION_BEGIN (no input)");
			break;
		case vfmAuthSessionEnd:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "AUTH_SESSION_END (no input)");
			break;
		case vfmCaptureStart:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_START (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmCaptureReadData:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_READ_DATA (no input)");
			break;
		case vfmCaptureProcessData:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_PROCESS_DATA (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmMatchImageToTemplates:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "MATCH_IMAGE_TO_TEMPLATES (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			for(int i=0; i < 30; i++) {
				if ((tci->cmd_custom[i].len == 0) || (tci->cmd_custom[i].addr == 0))
					break;
				__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "input template %d:", i);
				hex_dump((uint8_t*)ext_input_buf + tci->cmd_custom[i].addr - ext_input_addr, tci->cmd_custom[i].len);//ext_input_len);
			}
			break;
		case vfmPayloadRelease:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PAYLOAD_RELEASE (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "extra input:");
			hex_dump((uint8_t*)ext_input_buf, tci->cmd_custom[0].len);//ext_input_len);
			break;
		case vfmVendorDefinedOperation:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "VENDOR_DEFINED_OPERATION %08x (decode wen)", tci->vendor_cmd);
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmGetSpiMode:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "GET MODE");
			break;
		//Enrollment cases
		case vfmEnrollAddImage:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_ADD_IMAGE (NO INPUT)");
			break;
		case vfmEnrollBegin:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_BEGIN (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;	
		case vfmEnrollFinish:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_FINISH (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;
		case vfmPayloadBind:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PAYLOAD_BIND (decode wen)");
			hex_dump((uint8_t*)input_buf + (tci->input.addr - input_addr), tci->input.len);
			break;									
		default:
			break;
	}
}

static void try_decode_reply(tciMessageS5* tci) {
	uint32_t* buf = (uint32_t*)(output_buf + (tci->output.addr - output_addr));
	uint8_t* buf8 = (uint8_t*)buf;
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "OUTPUT_LEN: %08x, OUTPUT_ADDR: %08x", tci->output.len, tci->output.addr);
	switch (tci->return_cmd) {
		case vfmProvisionRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PROVISION (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmInitializeRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "INITIALIZE (no output)");
			break;
		case vfmUninitializeRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "UNINITIALIZE (no output)");
			break;
		case vfmDeviceInitializeRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "DEVICE_INITIALIZE (no output)");
			break;
		case vfmDeviceCalibrateRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "DEVICE_CALIBRATE (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmAuthSessionBeginRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "AUTH_SESSION_BEGIN (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmAuthSessionEndRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "AUTH_SESSION_END (no output)");
			break;
		case vfmCaptureStartRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_START (no output)");
			break;
		case vfmCaptureReadDataRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_READ_DATA (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmCaptureProcessDataRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "CAPTURE_PROCESS_DATA (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmMatchImageToTemplatesRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "MATCH_IMAGE_TO_TEMPLATES (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ext_output:");
			hex_dump((uint8_t*)ext_output_buf + (tci->ext_output.addr - ext_output_addr), tci->ext_output.len);
			break;
		case vfmPayloadReleaseRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PAYLOAD_RELEASE (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmVendorDefinedOperationRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "VENDOR_DEFINED_OPERATION (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmGetSpiModeRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "GET MODE RESPONSE: %02x", buf8[0]);
			break;
		//Enrollment cases
		case vfmEnrollAddImageRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_ADD_IMAGE (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmEnrollBeginRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_BEGIN (NO OUTPUT)");
			break;	
		case vfmEnrollFinishRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "ENROLL_FINISH (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;
		case vfmPayloadBindRsp:
			__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "PAYLOAD_BIND (decode wen)");
			hex_dump((uint8_t*)output_buf + (tci->output.addr - output_addr), tci->output.len);
			break;				
		default:
			break;
	}
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "RETURN CODE %08x", tci->return_code);
}

mcResult_t mcOpenDevMOD(uint32_t deviceId) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenDevice %d", deviceId);
	mcResult_t result = mcOpenDevice(deviceId);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenDevice return %d", result);
	return result;
}

mcResult_t mcCloseDevMOD(uint32_t deviceId) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcCloseDevice %d", deviceId);
	mcResult_t result = mcCloseDevice(deviceId);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcCloseDevice return %d", result);
	return result;
}

mcResult_t mcOpenSessMOD(mcSessionHandle_t *session, const mcUuid_t *uuid, uint8_t *tci, uint32_t tciLen) {
	char uuidstr[33] = "";
	char* tcistr;
	char onehex[3] = "";
	
	for(int i=0; i < 16; i++) {
		snprintf(onehex, 3, "%02x", uuid->value[i]);
		strcat(uuidstr, onehex);
	}

	tcistr = malloc(tciLen * 2 + 1); //two letters for each byte and zero byte end
	tcistr[0] = '\0';

	for(int i=0; i < tciLen; i++) {
		snprintf(onehex, 3, "%02x", tci[i]);
		strcat(tcistr, onehex);
	}

	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenSession UUID: %s. tciLen: %08x", uuidstr, tciLen);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenSession TCI: %p", tci);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenSession TCI: %s", tcistr);
	mcResult_t result = mcOpenSession(session, uuid, tci, tciLen);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcOpenSession return %d, sessionid: %08x, deviceid: %08x", result, session->sessionId, session->deviceId);
	if (uuid->value[4] == 0x00) {
		fp_session = session->sessionId;
		fp_tci = tci;
	}
	free(tcistr);
	return result;
}

mcResult_t mcCloseSessMOD(mcSessionHandle_t *session) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcCloseSession sessionid: %08x, deviceid: %08x", session->sessionId, session->deviceId);
	mcResult_t result = mcCloseSession(session);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcCloseSession return %d", result);
	return result;
}

mcResult_t mcNotMOD(mcSessionHandle_t *session) {
	char tcistr[sizeof(tciMessageS5) * 2 + 1];
	char onehex[3] = "";

	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcNotify sessionid: %08x, deviceid: %08x", session->sessionId, session->deviceId);
	if (session->sessionId == fp_session) {
		tcistr[0] = '\0';
		for(int i=0; i < sizeof(tciMessageS5); i++) {
			snprintf(onehex, 3, "%02x", fp_tci[i]);
			strcat(tcistr, onehex);
		}
		__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcNotify pre-send tci: %s", tcistr);

		try_decode_send((tciMessageS5*)fp_tci);
	}
	mcResult_t result = mcNotify(session);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcNotify return %d", result);
	return result;
}

mcResult_t mcWaitNotificatMOD(mcSessionHandle_t *session, int32_t timeout) {
	char tcistr[sizeof(tciMessageS5) * 2 + 1];
	char onehex[3] = "";
	
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcWaitNotification sessionid: %08x, deviceid: %08x, timeout: %08x", session->sessionId, session->deviceId, timeout);
	mcResult_t result = mcWaitNotification(session, timeout);
	if (session->sessionId == fp_session) {
		tcistr[0] = '\0';
		for(int i=0; i < sizeof(tciMessageS5); i++) {
			snprintf(onehex, 3, "%02x", fp_tci[i]);
			strcat(tcistr, onehex);
		}
		__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcWaitNotification post-send tci: %s", tcistr);

		try_decode_reply((tciMessageS5*)fp_tci);
	}
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcWaitNotification return %d", result);
	return result;
}

mcResult_t mcMallocMOD(uint32_t deviceId, uint32_t align, uint32_t len, uint8_t **wsm, uint32_t wsmFlags) {
	char* wsmstr;
	char onehex[3] = "";
	
	wsmstr = malloc(len * 2 + 1); //two letters for each byte and zero byte end
	wsmstr[0] = '\0';

	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMallocWSM deviceId: %08x, align: %08x, len: %08x, wsmFlags: %08x", deviceId, align, len, wsmFlags);
	mcResult_t result = mcMallocWsm(deviceId, align, len, wsm, wsmFlags);

	for(int i=0; i < len; i++) {
		snprintf(onehex, 3, "%02x", (*wsm)[i]);
		strcat(wsmstr, onehex);
	}
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMallocWSM %p, %p", wsm, *wsm);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMallocWSM %s", wsmstr);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMallocWSM return %d", result);
	free(wsmstr);
	return result;
}

mcResult_t mcFreeMOD(uint32_t deviceId, uint8_t *wsm) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcFreeWSM deviceId: %08x", deviceId);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcFreeWSM %p", wsm);
	mcResult_t result = mcFreeWsm(deviceId, wsm);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcFreeWSM return %d", result);
	return result;
}

mcResult_t mcMOD(mcSessionHandle_t *session, void *buf, uint32_t len, mcBulkMap_t *mapInfo) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMap, sessionid: %08x, deviceid: %08x, buf: %p, len: %08x", session->sessionId, session->deviceId, buf, len);
	mcResult_t result = mcMap(session, buf, len, mapInfo);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcMap return %d, addr=%04x, len=%04x", result, (uint32_t)mapInfo->sVirtualAddr, (uint32_t)mapInfo->sVirtualLen);
	
	if (input_addr == 0) {
		input_addr = (uint32_t)mapInfo->sVirtualAddr;
		input_len = mapInfo->sVirtualLen;
		input_buf = buf;
	} else if (output_addr == 0) {
		output_addr = (uint32_t)mapInfo->sVirtualAddr;
		output_len = mapInfo->sVirtualLen;
		output_buf = buf;
	} else if (ext_input_addr == 0) {
		ext_input_addr = (uint32_t)mapInfo->sVirtualAddr;
		ext_input_len = mapInfo->sVirtualLen;
		ext_input_buf = buf;
	} else if (ext_output_addr == 0) {
		ext_output_addr = (uint32_t)mapInfo->sVirtualAddr;
		ext_output_len = mapInfo->sVirtualLen;
		ext_output_buf = buf;
	}
	return result;
}

mcResult_t mcUnMOD(mcSessionHandle_t *session, void *buf, mcBulkMap_t *mapInfo) {
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcUnmap, sessionid: %08x, deviceid: %08x, buf: %p", session->sessionId, session->deviceId, buf);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcUnmap addr=%04x, len=%04x", (uint32_t)mapInfo->sVirtualAddr, (uint32_t)mapInfo->sVirtualLen);
	if ((uint32_t)mapInfo->sVirtualAddr == input_addr)
	{
		input_addr = 0;
		input_len = 0;
		input_buf = 0;
	}
	if ((uint32_t)mapInfo->sVirtualAddr == output_addr)
	{
		output_addr = 0;
		output_len = 0;
		output_buf = 0;
	}
	if ((uint32_t)mapInfo->sVirtualAddr == ext_input_addr)
	{
		ext_input_addr = 0;
		ext_input_len = 0;
		ext_input_buf = 0;
	}
	if ((uint32_t)mapInfo->sVirtualAddr == ext_output_addr)
	{
		ext_output_addr = 0;
		ext_output_len = 0;
		ext_output_buf = 0;
	}
	mcResult_t result = mcUnmap(session, buf, mapInfo);
	__android_log_print(ANDROID_LOG_VERBOSE, "FPSHIM", "mcUnmap return %d", result);
	return result;
}
