#ifndef LIB_MC_FP_LOG_H
#define LIB_MC_FP_LOG_H

mcResult_t mcOpenDevMOD(uint32_t deviceId);
mcResult_t mcCloseDevMOD(uint32_t deviceId);
mcResult_t mcOpenSessMOD(mcSessionHandle_t *session, const mcUuid_t *uuid, uint8_t *tci, uint32_t tciLen);
mcResult_t mcCloseSessMOD(mcSessionHandle_t *session);
mcResult_t mcNotMOD(mcSessionHandle_t *session);
mcResult_t mcWaitNotificatMOD(mcSessionHandle_t *session, int32_t timeout);
mcResult_t mcMallocMOD(uint32_t deviceId, uint32_t align, uint32_t len, uint8_t **wsm, uint32_t wsmFlags);
mcResult_t mcFreeMOD(uint32_t deviceId, uint8_t *wsm);
mcResult_t mcMOD(mcSessionHandle_t *session, void *buf, uint32_t len, mcBulkMap_t *mapInfo);
mcResult_t mcUnMOD(mcSessionHandle_t *session, void *buf, mcBulkMap_t *mapInfo);

#endif
