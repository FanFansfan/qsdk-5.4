/*
 * Copyright (c) 2015-2021 Qualcomm Technologies, Inc.
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <time.h>
#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
#include <fcntl.h>
#endif
#include <inttypes.h>
#include <errno.h>

#include <qmi_idl_lib_internal.h>
#ifdef ANDROID
#include <qmi_client_instance_defs.h>
#else
#include "qmi_client.h"
#endif
#ifdef ANDROID
/* peripheral manager */
#include <pm-service.h>
#include <mdm_detect.h>
#endif

#include "debug.h"
#include "wlfw_qmi_client.h"
#include "wlan_firmware_service_v01.h"
#ifdef ANDROID
#include "device_management_service_v01.h"
#endif
#include "cnss_plat.h"

#ifdef CONFIG_NO_PM
typedef enum MdmType {
    MDM_TYPE_EXTERNAL = 0,
    MDM_TYPE_INTERNAL,
    SUBSYS_TYPE_SENSOR,
    SUBSYS_TYPE_SPSS,
} MdmType;
#endif

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#ifdef USE_GLIB
#undef FALSE
#endif

#define WLFW_CLIENT_ID		0x444d4f4e
#define WLFW_TIMEOUT_MS		(10000)
#define WLFW_TIMEOUT_DMS_MS	(3000)
#define WLFW_LOW_MEM_FILE_LEN	(1*1024*1024)
#define MAX_FILE_NAME_LEN	15
#define DEFAULT_BDF_FILE	"bdwlan.bin"
#define REGDB_BDF_FILE		"regdb.bin"
#define BDF_FILE		"bdwlan."
#define HOLI_TARGET_NAME	"holi"
#define TARGET_PLATFORM_PROPERTY	"ro.board.platform"
#define CAL_FILE		"/data/vendor/wifi/wlfw_cal_"
#define DEFAULT_QDSS_CONFIG_PATH "/data/vendor/wifi/"
#define QDSS_TRACE_CONFIG_FILE	"qdss_trace_config.bin"
#define QDSS_TRACE_CONFIG_FILE_PREFIX "qdss_trace_config"
#define QDSS_TRACE_CONFIG_FILE_SUFFIX ".bin"
#define QDSS_TRACE_CONFIG_FILE_NEW \
			"/vendor/firmware_mnt/image/qdss_trace_config.cfg"
#define FALSE			1
#define WLFW_MAX_BDF_RETRY	2

#define CAL_DOWNLOAD_RETRY_MAX_TIMES	3
#define CAL_DOWNLOAD_RETRY_DELAY_US	500000
#define WLFW_QDSS_MEM_READY_TIMEOUT 10

#define CNSS_WLFW_QMI_CONNECTED		BIT(0)
#define CNSS_MSA_READY			BIT(1)
#define CNSS_FW_MEM_READY		BIT(2)
#define CNSS_BDF_DOWNLOAD_DONE		BIT(3)
#define CNSS_QDSS_MEM_READY		BIT(4)
#define CNSS_QDSS_STARTED		BIT(5)

#define CNSS_IS_WLFW_QMI_CONNECTED(_state) ((_state) & CNSS_WLFW_QMI_CONNECTED)
#define CNSS_IS_MSA_READY(_state) ((_state) & CNSS_MSA_READY)
#define CNSS_IS_FW_MEM_READY(_state) ((_state) & CNSS_FW_MEM_READY)
#define CNSS_IS_BDF_DOWNLOAD_DONE(_state) ((_state) & CNSS_BDF_DOWNLOAD_DONE)
#define CNSS_IS_QDSS_MEM_READY(_state) ((_state) & CNSS_QDSS_MEM_READY)
#define CNSS_IS_QDSS_STARTED(_state) ((_state) & CNSS_QDSS_STARTED)

#define WLAN_BOARD_ID_INDEX 0x100
#define QMI_ERR_PLAT_CCPM_CLK_INIT_FAILED 0x77

#define MAX_PM_CLIENT 2

#define UMC_CHIP_ID  0x4320
#define BDWLAN_SIZE  6
#define CNSS_ANDROID_PROPERTY_MAX 128

const char *bdf_dir_list[] = {"/firmware/image/", "/vendor/firmware/",
				"/vendor/firmware_mnt/image/", NULL};

uint16_t g_instance_id_array[MAX_NUM_RADIOS] = {QMI_CLIENT_INSTANCE_ANY,
						QMI_CLIENT_INSTANCE_ANY,
						QMI_CLIENT_INSTANCE_ANY};

#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
const char debug_file[] =  "/sys/kernel/debug/cnss/qmi_record";
#endif

struct cal_data {
	wlfw_cal_temp_id_enum_v01 cal_id;
	uint32_t total_size;
	uint8_t *data;
};

struct wlan_mac_addr {
	uint8_t mac_addr_valid;
	uint8_t mac_addr[QMI_WLFW_MAC_ADDR_SIZE_V01];
};

enum cnss_bdf_type {
	CNSS_BDF_BIN,
	CNSS_BDF_ELF,
	CNSS_BDF_REGDB = 4,
	CNSS_BDF_DUMMY = 255,
};

struct pm_data {
	void *pm_handle;
	MdmType type;
};

struct wlfw_client_data {
	qmi_idl_service_object_type svc_obj;
	qmi_client_type clnt_handler;
	qmi_service_instance instance_id;
	int svc_running;
	int dms_running;
	struct pm_data pm_client[MAX_PM_CLIENT];
	uint32_t state;
	pthread_t thread_id;
#ifdef CONFIG_READ_NV_MAC_ADDR
	pthread_t thread_id_dms;
	pthread_mutex_t dms_mutex;
	pthread_cond_t dms_cond;
#endif
	pthread_mutex_t mutex;
	bool cond_signaled;
	pthread_cond_t cond;
	pthread_cond_t cond_rsp;
	struct cnss_evt_queue evt_q;
	pthread_mutex_t cal_mutex;
	struct cal_data cal_data_array[QMI_WLFW_MAX_NUM_CAL_V01];
	wlfw_rf_chip_info_s_v01 chip_info;
	wlfw_rf_board_info_s_v01 board_info;
	wlfw_soc_info_s_v01 soc_info;
	wlfw_fw_version_info_s_v01 fw_version_info;
	struct wlan_mac_addr mac_addr;
	uint8_t index;
	uint32_t qdss_max_file_len;
};
static struct wlfw_client_data client_data[MAX_NUM_RADIOS];

static struct wlfw_client_data *get_gdata_by_instance_id(uint32_t instance_id)
{
	int i;

	if (instance_id == 0)
		return &client_data[0];

	for (i = 0; i < MAX_NUM_RADIOS; i++) {
		if (client_data[i].instance_id == instance_id)
			return &client_data[i];
	}

	wsvc_printf_err("Failed to get gdata for instance_id %d", instance_id);
	return NULL;
}

#ifdef CONFIG_NO_PM
int pm_init(struct wlfw_client_data *gdata, MdmType type, const char *name)
{
	return 0;
}
void pm_deinit(struct wlfw_client_data *gdata, MdmType type)
{
	return;
}
#else
int pm_vote(void *pm_handle)
{
	int ret = 0;

	if (!pm_handle) {
		wsvc_printf_err("%s: pm_handle is NULL", __func__);
		ret = -1;
		goto out;
	}

	wsvc_printf_dbg("%s: Vote for modem", __func__);

	ret = pm_client_connect(pm_handle);
	if (ret)
		wsvc_printf_err("%s: Failed to vote, ret = %d",
				__func__, ret);
out:
	return ret;
}

void pm_release_vote(void *pm_handle)
{
	if (!pm_handle) {
		wsvc_printf_err("%s: pm_handle is NULL", __func__);
		return;
	}

	wsvc_printf_dbg("%s: Release vote for modem", __func__);

	pm_client_disconnect(pm_handle);
}

void pm_event_notifier(void *client_cookie, enum pm_event event)
{
	struct pm_data *data = client_cookie;

	if (!data)
		return;

	wsvc_printf_dbg("%s: event %d received on pm[%d]",
			__func__, event, data->type);

	if (data->pm_handle)
		pm_client_event_acknowledge(data->pm_handle, event);
}

int pm_init(struct wlfw_client_data *gdata, MdmType type, const char *name)
{
	struct dev_info devinfo;
	int i, ret;
	enum pm_event event;
	int found = 0;
	struct pm_data *data = NULL;

	wsvc_printf_dbg("%s: Starting pm[%d] service", __func__, type);

	if (type >= MAX_PM_CLIENT) {
		wsvc_printf_err("%s: Invalid MDM type %d\n", __func__, type);
		return -1;
	}

	data = &gdata->pm_client[type];
	data->type = type;

	ret = get_system_info(&devinfo);
	if (ret != RET_SUCCESS) {
		wsvc_printf_err("%s: Failed to get device info, ret = %d",
				__func__, ret);
		goto out;
	}

	wsvc_printf_dbg("%s: devinfo.num_modems = %d\n",
			__func__, devinfo.num_modems);
	for (i = 0; i < devinfo.num_modems; i++) {
		if (devinfo.mdm_list[i].type == type &&
		    (!name ||
		     strcmp(devinfo.mdm_list[i].mdm_name, name) == 0)) {
			wsvc_printf_dbg("%s: Found modem: type:%d name:%s",
					__func__, devinfo.mdm_list[i].type,
					devinfo.mdm_list[i].mdm_name);
			ret = pm_client_register(pm_event_notifier,
						 data,
						 devinfo.mdm_list[i].mdm_name,
						 "cnss-daemon",
						 &event,
						 &data->pm_handle);
			if (ret != PM_RET_SUCCESS) {
				wsvc_printf_err("%s: Failed to register pm client, ret = %d",
						__func__, ret);
				continue;
			}
			found = 1;
			break;
		}
	}

	if (found == 0) {
		ret = -1;
		goto out;
	}

	ret = pm_vote(data->pm_handle);

out:
	return ret;
}

void pm_deinit(struct wlfw_client_data *gdata, MdmType type)
{
	void *pm_handle = NULL;

	wsvc_printf_dbg("%s: Exit pm[%d] service\n", __func__, type);

	pm_handle = gdata->pm_client[type].pm_handle;

	pm_release_vote(pm_handle);

	if (pm_handle)
		pm_client_unregister(pm_handle);

	gdata->pm_client[type].pm_handle = NULL;
}
#endif

static int wlfw_send_ind_register_req(uint64_t *fw_status,
				      struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_ind_register_req_msg_v01 req;
	wlfw_ind_register_resp_msg_v01 resp;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	wsvc_printf_dbg("%s", __func__);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.client_id_valid = 1;
	req.client_id = WLFW_CLIENT_ID;
	req.fw_ready_enable_valid = 1;
	req.fw_ready_enable = 1;

	if (gdata->instance_id != MOSELLE_ID) {
		req.initiate_cal_download_enable_valid = 1;
		req.initiate_cal_download_enable = 1;
		req.initiate_cal_update_enable_valid = 1;
		req.initiate_cal_update_enable = 1;
	}

	if (gdata->instance_id == ADRASTEA_ID) {
		req.msa_ready_enable_valid = 1;
		req.msa_ready_enable = 1;
	}

	if (gdata->instance_id == NAPIER_ID ||
	    gdata->instance_id == HASTINGS_ID ||
	    gdata->instance_id == HAWKEYE_ID ||
	    gdata->instance_id == MOSELLE_ID ||
	    gdata->instance_id == PINE_1_ID ||
	    gdata->instance_id == PINE_2_ID ||
	    gdata->instance_id == SPRUCE_1_ID ||
	    gdata->instance_id == SPRUCE_2_ID) {
		req.fw_mem_ready_enable_valid = 1;
		req.fw_mem_ready_enable = 1;
		req.qdss_mem_ready_enable_valid = 1;
		req.qdss_mem_ready_enable = 1;
	}

	if (gdata->instance_id != MOSELLE_ID &&
	    gdata->instance_id != NAPIER_ID &&
	    gdata->instance_id != HASTINGS_ID) {
		req.qdss_trace_save_enable_valid = 1;
		req.qdss_trace_save_enable = 1;
	}

	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_IND_REGISTER_REQ_V01, rc, 0);
	rc = qmi_client_send_msg_sync(gdata->clnt_handler,
				      QMI_WLFW_IND_REGISTER_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);

	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("%s: rc %d, result %d, error %d",
				__func__,
				rc,
				resp.resp.result,
				resp.resp.error);
		if (resp.resp.result)
			rc = -resp.resp.result;
		resp_err_msg = resp.resp.error;
		goto out;
	}

	if (resp.fw_status_valid)
		*fw_status = resp.fw_status;

	wsvc_printf_dbg("%s: result %d, error %d, fw_status_valid %u, fw_status 0x%" PRIx64,
			__func__,
			resp.resp.result,
			resp.resp.error,
			resp.fw_status_valid,
			resp.fw_status);

out:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_IND_REGISTER_REQ_V01, rc, resp_err_msg);
	return rc;
}

static int wlfw_send_cap_req(struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_cap_req_msg_v01 req;
	wlfw_cap_resp_msg_v01 resp;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	wsvc_printf_dbg("%s", __func__);
	memset(&resp, 0, sizeof(resp));
	daemon_qmihist_record(gdata->instance_id, QMI_WLFW_CAP_REQ_V01, rc, 0);

	rc = qmi_client_send_msg_sync(gdata->clnt_handler,
				      QMI_WLFW_CAP_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);

	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("%s: rc %d, result %d, error %d",
				__func__,
				rc,
				resp.resp.result,
				resp.resp.error);
		resp_err_msg = resp.resp.error;
		if (resp.resp.error == QMI_ERR_PLAT_CCPM_CLK_INIT_FAILED) {
			wsvc_printf_err("RF card Not Present");
			rc = -EAGAIN;
			goto out;
		}
		if (resp.resp.result)
			rc = -resp.resp.result;
		goto out;
	}

	wsvc_printf_dbg("%s: result %d, error %d", __func__,
				resp.resp.result,
				resp.resp.error);

	/* store cap locally */
	if (resp.chip_info_valid)
		gdata->chip_info = resp.chip_info;
	if (resp.board_info_valid)
		gdata->board_info = resp.board_info;
	else
		gdata->board_info.board_id = 0xFF;
	if (resp.soc_info_valid)
		gdata->soc_info = resp.soc_info;
	if (resp.fw_version_info_valid)
		gdata->fw_version_info = resp.fw_version_info;

	wsvc_printf_info("%s: chip_id: 0x%0x, chip_family 0x%x,"
			 " board_id: 0x%0x, soc_id: 0x%0x,"
			 " fw_version: 0x%0x, fw_build_timestamp: %s",
			 __func__,
			 gdata->chip_info.chip_id,
			 gdata->chip_info.chip_family,
			 gdata->board_info.board_id,
			 gdata->soc_info.soc_id,
			 gdata->fw_version_info.fw_version,
			 gdata->fw_version_info.fw_build_timestamp);

out:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAP_REQ_V01, rc, resp_err_msg);
	return rc;
}

static int wlfw_send_bdf_download_req(enum cnss_bdf_type bdf_type,
				      struct wlfw_client_data *gdata)
{
	int i, rc = FALSE;
	wlfw_bdf_download_req_msg_v01 req;
	wlfw_bdf_download_resp_msg_v01 resp;
	FILE *file = NULL;
	unsigned char *buffer, *temp;
	unsigned int file_len, remaining;
	char filename[MAX_FILE_NAME_LEN];
	char filefullpath[CNSS_MAX_FILE_PATH];
#ifdef ANDROID
	int ret;
	char target_name[MAX_PROPERTY_SIZE];
#endif

	wsvc_printf_dbg("%s", __func__);

	if (CNSS_BDF_BIN == bdf_type) {
#ifdef ANDROID
		/* Below arrangement is special requirement for mannar in which even if
		 * board ID is 0x5f, 0x66 board ID's bdf should be loaded*/
		ret = property_get(TARGET_PLATFORM_PROPERTY, target_name, "");
		if (ret > MAX_PROPERTY_SIZE)
			wsvc_printf_err("property [%s] has size [%d] that exceeds max [%d]",
					TARGET_PLATFORM_PROPERTY, ret,
					MAX_PROPERTY_SIZE);
		else if ((gdata->board_info.board_id == 0x5f) &&
			 !(strcmp(HOLI_TARGET_NAME, target_name)))
			gdata->board_info.board_id = 0x66;
#endif
		/* retrive bdf file name from capability */
		if (gdata->board_info.board_id == 0xFF) {
			snprintf(filename, sizeof(filename),
				 "%s", DEFAULT_BDF_FILE);
		} else {
			if (gdata->board_info.board_id >= WLAN_BOARD_ID_INDEX) {
				snprintf(filename, sizeof(filename),
					 BDF_FILE"%03x",
					 gdata->board_info.board_id);
			} else {
				snprintf(filename, sizeof(filename),
					 BDF_FILE"b%02x",
					 gdata->board_info.board_id);
			}
		}

		if (gdata->chip_info.chip_id == UMC_CHIP_ID) {
			memmove(filename + BDWLAN_SIZE + 1, filename + BDWLAN_SIZE, BDWLAN_SIZE - 1);
			filename[BDWLAN_SIZE] = 'u';
			filename[MAX_FILE_NAME_LEN - 1] = '\0';
			wsvc_printf_info("%s: Updated BDF file : %s", __func__, filename);
		}
	} else {
		snprintf(filename, sizeof(filename),
			 "%s", REGDB_BDF_FILE);
	}

	wsvc_printf_info_high("%s: BDF file : %s", __func__, filename);

	for (i = 0; bdf_dir_list[i]; i++) {
		snprintf(filefullpath, sizeof(filefullpath),
			"%s%s", bdf_dir_list[i], filename);
		wsvc_printf_dbg("%s: Looking for BDF file: %s",
			__func__, filefullpath);
		file = fopen(filefullpath, "rb");
		if (file != NULL) {
			wsvc_printf_dbg("%s: BDF file found: %s",
			__func__, filefullpath);
			break;
		}
	}
	if (!file) {
		wsvc_printf_err("%s: Failed to find BDF file %s", __func__,
			filename);
		rc = -1;
		goto end;
	}

	fseek(file, 0, SEEK_END);
	file_len = ftell(file);
	fseek(file, 0, SEEK_SET);

	buffer = (unsigned char *)malloc(file_len);
	if (buffer == NULL) {
		wsvc_printf_err("%s: Fail to alloc memory for BDF file",
					 __func__);
		rc = -1;
		goto memory_alloc_fail;
	}
	if (fread(buffer, 1, file_len, file) != file_len) {
		wsvc_printf_err("%s: Fail to read BDF file", __func__);
		rc = -1;
		goto read_fail;
	}
	fclose(file);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	temp = buffer;
	remaining = file_len;
	while (remaining) {
		req.valid = 1;
		/* file id should retrive from capability */
		req.file_id_valid = 1;
		req.file_id = 0;
		req.total_size_valid = 1;
		req.total_size = file_len;
		req.seg_id_valid = 1;
		req.data_valid = 1;
		req.end_valid = 1;
		req.bdf_type_valid = 1;
		req.bdf_type = bdf_type;

		if (remaining > QMI_WLFW_MAX_DATA_SIZE_V01) {
			req.data_len = QMI_WLFW_MAX_DATA_SIZE_V01;
		} else {
			req.data_len = remaining;
			req.end = 1;
		}
		memcpy(req.data, temp, req.data_len);

		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
					      QMI_WLFW_BDF_DOWNLOAD_REQ_V01,
					      &req,
					      sizeof(req),
					      &resp,
					      sizeof(resp),
					      WLFW_TIMEOUT_MS);
		if (rc != QMI_NO_ERR) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
			rc = FALSE;
			goto out;
		}

		remaining -= req.data_len;
		temp += req.data_len;
		req.seg_id++;
	}

	wsvc_printf_info("%s: bdf type %d,result %d, error %d", __func__,
				bdf_type,
				resp.resp.result,
				resp.resp.error);
out:
        free(buffer);
        buffer = NULL;
        if (QMI_ERR_INVALID_ARG_V01 == resp.resp.error) {
		wsvc_printf_dbg("%s: Response failure : 0x%0x",
				__func__, resp.resp.error);
		rc = FALSE;
        }
	return rc;

read_fail:
	free(buffer);
	buffer = NULL;
memory_alloc_fail:
	fclose(file);
end:
	return rc;
}

static int wlfw_send_cal_report_req(struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_cal_report_req_msg_v01 req;
	wlfw_cal_report_resp_msg_v01 resp;
	int i, j = 0;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	wsvc_printf_dbg("%s", __func__);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.cal_remove_supported_valid = 1;
#ifdef CAL_DATA_REMOVE
	req.cal_remove_supported = 1;
#else
	req.cal_remove_supported = 0;
#endif

	pthread_mutex_lock(&(gdata->cal_mutex));
	for(i = 0; i < QMI_WLFW_MAX_NUM_CAL_V01; i++) {
		if (gdata->cal_data_array[i].total_size &&
		    gdata->cal_data_array[i].data) {
			req.meta_data[j] = gdata->cal_data_array[i].cal_id;
			j++;
		}
	}
	pthread_mutex_unlock(&(gdata->cal_mutex));

	req.meta_data_len = j;
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_REPORT_REQ_V01, rc, 0);
	rc = qmi_client_send_msg_sync(gdata->clnt_handler,
				      QMI_WLFW_CAL_REPORT_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);
	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("%s: rc %d, result %d, error %d",
				__func__,
				rc,
				resp.resp.result,
				resp.resp.error);
		if (resp.resp.result)
			rc = -resp.resp.result;
		resp_err_msg = resp.resp.error;
		goto out;
	}

	wsvc_printf_dbg("%s: result %d, error %d", __func__,
				resp.resp.result,
				resp.resp.error);

out:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_REPORT_REQ_V01, rc, resp_err_msg);
	return rc;
}

#ifdef CONFIG_READ_NV_MAC_ADDR
static int wlfw_send_mac_addr_req(struct wlfw_client_data *gdata)
{
	int rc;
	wlfw_mac_addr_req_msg_v01 req;
	wlfw_mac_addr_resp_msg_v01 resp;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.mac_addr_valid = 1;
	memcpy(req.mac_addr, gdata->mac_addr.mac_addr,
	       QMI_WLFW_MAC_ADDR_SIZE_V01);

	wsvc_printf_mac_addr(MSG_DEBUG, "Sending MAC address to FW",
			     gdata->mac_addr.mac_addr);

	rc = qmi_client_send_msg_sync(gdata->clnt_handler,
				      QMI_WLFW_MAC_ADDR_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);
	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("Failed to send MAC address: rc %d, result %d, error %d",
				rc,
				resp.resp.result,
				resp.resp.error);
		if (resp.resp.result)
			rc = -resp.resp.result;
		goto out;
	}

	wsvc_printf_dbg("%s: result %d, error %d", __func__,
			resp.resp.result,
			resp.resp.error);

out:
	return rc;
}
#endif

static struct cal_data *find_cal_file(wlfw_cal_temp_id_enum_v01 cal_id,
				      struct wlfw_client_data *gdata)
{
	int i;

	for (i = 0; i < QMI_WLFW_MAX_NUM_CAL_V01; i++) {
		if (gdata->cal_data_array[i].cal_id == cal_id) {
			if (gdata->cal_data_array[i].total_size &&
			    gdata->cal_data_array[i].data)
				return &gdata->cal_data_array[i];
		}
	}

	return NULL;
}

static void free_cal_file(struct wlfw_client_data *gdata)
{
	int i;

	pthread_mutex_lock(&(gdata->cal_mutex));
	for (i = 0; i < QMI_WLFW_MAX_NUM_CAL_V01; i++) {
		gdata->cal_data_array[i].cal_id = 0;
		gdata->cal_data_array[i].total_size = 0;
		if (gdata->cal_data_array[i].data) {
			wsvc_printf_info("Start to free CAL table id: %d", i);
			free(gdata->cal_data_array[i].data);
			gdata->cal_data_array[i].data = NULL;
			wsvc_printf_info("End to free CAL table id: %d", i);
		}
	}
	pthread_mutex_unlock(&(gdata->cal_mutex));
}

static int wlfw_send_cal_download_req(void *data,
				      struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_cal_download_req_msg_v01 req;
	wlfw_cal_download_resp_msg_v01 resp;
	struct cal_data *p_cal_data = NULL;
	unsigned char *temp;
	unsigned int remaining;
	int retry = 0;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	wlfw_initiate_cal_download_ind_msg_v01 *ind = data;
	wlfw_cal_temp_id_enum_v01 cal_id = ind->cal_id;

	wsvc_printf_dbg("%s: cal_id %u", __func__, cal_id);

	pthread_mutex_lock(&(gdata->cal_mutex));
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	p_cal_data = find_cal_file(cal_id, gdata);
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_DOWNLOAD_REQ_V01, rc, 0);
	if (p_cal_data == NULL) {
		req.total_size_valid = 1;
		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
					      QMI_WLFW_CAL_DOWNLOAD_REQ_V01,
					      &req,
					      sizeof(req),
					      &resp,
					      sizeof(resp),
					      WLFW_TIMEOUT_MS);
		if ((rc != QMI_NO_ERR) ||
		   (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
		}
		wsvc_printf_dbg("%s: result %d, error %d", __func__,
					resp.resp.result,
					resp.resp.error);
		goto out;
	}

	temp = p_cal_data->data;
	remaining = p_cal_data->total_size;
	while (remaining) {
retry_dl:
		req.valid = 1;
		req.file_id_valid = 1;
		req.file_id = p_cal_data->cal_id;
		req.total_size_valid = 1;
		req.total_size = p_cal_data->total_size;
		req.seg_id_valid = 1;
		req.data_valid = 1;
		req.end_valid = 1;
		if (remaining > QMI_WLFW_MAX_DATA_SIZE_V01) {
			req.data_len = QMI_WLFW_MAX_DATA_SIZE_V01;
		} else {
			req.data_len = remaining;
			req.end = 1;
		}
		memcpy(req.data, temp, req.data_len);

		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
					      QMI_WLFW_CAL_DOWNLOAD_REQ_V01,
					      &req,
					      sizeof(req),
					      &resp,
					      sizeof(resp),
					      WLFW_TIMEOUT_MS);
		if ((rc != QMI_NO_ERR) ||
		    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
			resp_err_msg = resp.resp.error;
			if (resp.resp.error == QMI_ERR_NO_MEMORY_V01 &&
			    retry++ < CAL_DOWNLOAD_RETRY_MAX_TIMES) {
				wsvc_printf_info("%s: Failed to download CAL seq#%d, retry#%d",
						 __func__, req.seg_id, retry);
				usleep(CAL_DOWNLOAD_RETRY_DELAY_US * retry);
				goto retry_dl;
			}

			goto out;
		}

		remaining -= req.data_len;
		temp += req.data_len;
		req.seg_id++;
		retry = 0;
	}

	wsvc_printf_dbg("%s: result %d, error %d", __func__,
				resp.resp.result,
				resp.resp.error);
out:
	pthread_mutex_unlock(&(gdata->cal_mutex));
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_DOWNLOAD_REQ_V01, rc, resp_err_msg);
	return rc;
}

static int wlfw_send_cal_update_req(void *data,
				    struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_cal_update_req_msg_v01 req;
	wlfw_cal_update_resp_msg_v01 resp;
	unsigned char *p_cal_data_temp, *p_cal_data = NULL;
	unsigned int remaining;
	char filename[CNSS_MAX_FILE_PATH];
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	wlfw_initiate_cal_update_ind_msg_v01 *ind = data;
	wlfw_cal_temp_id_enum_v01 cal_id = ind->cal_id;
	unsigned int total_size = ind->total_size;

	wsvc_printf_dbg("%s: cal_id %u, total_size %d", __func__, ind->cal_id,
			ind->total_size);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	if (cal_id < 0 || cal_id >= QMI_WLFW_MAX_NUM_CAL_V01) {
		wsvc_printf_err("%s: Invalid Cal ID %u", __func__, cal_id);
		rc = -1;
		goto end;
	}

	p_cal_data = (unsigned char *)malloc(total_size);
	if (p_cal_data == NULL) {
		wsvc_printf_err("%s: Fail to alloc mem for cal file", __func__);
		rc = -1;
		goto end;
	}

	remaining = total_size;
	p_cal_data_temp = p_cal_data;
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_UPDATE_REQ_V01, rc, 0);

	while (remaining && resp.end == 0) {
		req.cal_id = cal_id;
		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
					      QMI_WLFW_CAL_UPDATE_REQ_V01,
					      &req,
					      sizeof(req),
					      &resp,
					      sizeof(resp),
					      WLFW_TIMEOUT_MS);
		if ((rc != QMI_NO_ERR) ||
		   (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
			resp_err_msg = resp.resp.error;
			goto fail;
		}

		wsvc_printf_dbg("%s: result %d, error %d", __func__,
					resp.resp.result,
					resp.resp.error);

		if ((resp.file_id_valid == 1 && resp.file_id == cal_id)
		   && (resp.total_size_valid == 1 && resp.total_size == total_size)
		   && (resp.seg_id_valid == 1 && resp.seg_id == req.seg_id)
		   && (resp.data_valid == 1 && resp.data_len <= QMI_WLFW_MAX_DATA_SIZE_V01)) {
			memcpy(p_cal_data_temp, resp.data, resp.data_len);
		} else {
			wsvc_printf_err("%s: Unmatched cal data, "
					"Expect file_id %u, total_size %u, "
					"seg_id %u, Recv file_id_valid %u, "
					"file_id %u, total_size_valid %u, "
					"total_size %u, seg_id_valid %u, "
					"seg_id %u, data_len_valid %u, "
					"data_len %u",
					__func__,
					cal_id, total_size, req.seg_id,
					resp.file_id_valid,
					resp.file_id,
					resp.total_size_valid,
					resp.total_size,
					resp.seg_id_valid,
					resp.seg_id,
					resp.data_valid,
					resp.data_len);
			rc = -1;
			goto fail;
		}
		remaining -= resp.data_len;
		p_cal_data_temp += resp.data_len;
		req.seg_id++;
	}

	if (remaining == 0 && (resp.end_valid && resp.end)) {
		pthread_mutex_lock(&(gdata->cal_mutex));
		gdata->cal_data_array[cal_id].cal_id = cal_id;
		gdata->cal_data_array[cal_id].total_size = total_size;
		if (gdata->cal_data_array[cal_id].data)
			free(gdata->cal_data_array[cal_id].data);
		gdata->cal_data_array[cal_id].data = p_cal_data;
		if (gdata->instance_id == PINE_1_ID ||
		    gdata->instance_id == PINE_2_ID)
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d_qcn9000_pci%d.bin", cal_id,
				 (gdata->instance_id - PINE_1_ID));
		else if (gdata->instance_id == SPRUCE_1_ID ||
			 gdata->instance_id == SPRUCE_2_ID)
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d_qcn6122_%d.bin", cal_id,
				 (gdata->instance_id - SPRUCE_1_ID));
		else
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d.bin", cal_id);
		cnss_plat_save_file(filename, p_cal_data, total_size, false,
				    CNSS_MAX_FILE_LEN);
		pthread_mutex_unlock(&(gdata->cal_mutex));
		goto end;
	} else {
		wsvc_printf_err("%s: Cal file corrupted: remaining %u, "
				"end_valid %u, end %u",	__func__,
				remaining, resp.end_valid, resp.end);
		rc = -1;
		goto fail;
	}

fail:
	free(p_cal_data);
end:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_CAL_UPDATE_REQ_V01, rc, resp_err_msg);
	return rc;
}

static int wlfw_send_qdss_trace_data_req(void *data,
					 struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	wlfw_qdss_trace_data_req_msg_v01 req;
	wlfw_qdss_trace_data_resp_msg_v01 resp;
	unsigned char *p_qdss_trace_data_temp, *p_qdss_trace_data = NULL;
	unsigned int remaining;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;
	char full_path_filename[CNSS_MAX_FILE_PATH];
	char *file_suffix = NULL;
	char file_prefix[QMI_WLFW_MAX_STR_LEN_V01] = {};

	wlfw_qdss_trace_save_ind_msg_v01 *ind = data;
	unsigned int total_size = ind->total_size;
	char *file_name = ind->file_name;

	if (ind->source != 1) {
		wsvc_printf_info("%s: Indication not for daemon", __func__);
		return -EINVAL;
	}

	wsvc_printf_dbg("%s: source %u, total_size %d, file_name %s",
			__func__, ind->source, ind->total_size, ind->file_name);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	p_qdss_trace_data = (unsigned char *)malloc(total_size);
	if (p_qdss_trace_data == NULL) {
		wsvc_printf_err("%s: Fail to alloc mem for qdss trace file",
				__func__);
		rc = -1;
		goto end;
	}

	remaining = total_size;
	p_qdss_trace_data_temp = p_qdss_trace_data;
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_DATA_REQ_V01, 0, 0);
	while (remaining && resp.end == 0) {
		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
					      QMI_WLFW_QDSS_TRACE_DATA_REQ_V01,
					      &req,
					      sizeof(req),
					      &resp,
					      sizeof(resp),
					      WLFW_TIMEOUT_MS);
		if ((rc != QMI_NO_ERR) ||
		   (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
			resp_err_msg = resp.resp.error;
			goto fail;
		}

		wsvc_printf_dbg("%s: result %d, error %d", __func__,
					resp.resp.result,
					resp.resp.error);

		if ((resp.total_size_valid == 1 &&
		     resp.total_size == total_size)
		   && (resp.seg_id_valid == 1 && resp.seg_id == req.seg_id)
		   && (resp.data_valid == 1 &&
		       resp.data_len <= QMI_WLFW_MAX_DATA_SIZE_V01)) {
			memcpy(p_qdss_trace_data_temp,
			       resp.data, resp.data_len);
		} else {
			wsvc_printf_err("%s: Unmatched qdss trace data, "
					"Expect total_size %u, "
					"seg_id %u, Recv total_size_valid %u, "
					"total_size %u, seg_id_valid %u, "
					"seg_id %u, data_len_valid %u, "
					"data_len %u",
					__func__,
					total_size, req.seg_id,
					resp.total_size_valid,
					resp.total_size,
					resp.seg_id_valid,
					resp.seg_id,
					resp.data_valid,
					resp.data_len);
			rc = -1;
			goto fail;
		}

		remaining -= resp.data_len;
		p_qdss_trace_data_temp += resp.data_len;
		req.seg_id++;
	}

	if (remaining == 0 && (resp.end_valid && resp.end)) {
		if (!file_name) {
			snprintf(full_path_filename, sizeof(full_path_filename),
				 CNSS_DEFAULT_QDSS_TRACE_FILE);
		} else {
			file_suffix = strstr(file_name, ".bin");
			if (file_suffix && gdata->instance_id == PINE_1_ID) {
				strlcpy(file_prefix, file_name,
					(file_suffix - &file_name[0]) + 1);
				snprintf(full_path_filename,
					 sizeof(full_path_filename),
					 "/data/vendor/wifi/%s_qcn9000_pci0%s",
					 file_prefix, file_suffix);
			} else if (file_suffix &&
				   gdata->instance_id == PINE_2_ID) {
				strlcpy(file_prefix, file_name,
					(file_suffix - &file_name[0]) + 1);
				snprintf(full_path_filename,
					 sizeof(full_path_filename),
					 "/data/vendor/wifi/%s_qcn9000_pci1%s",
					 file_prefix, file_suffix);
			} else {
				snprintf(full_path_filename,
					 sizeof(full_path_filename),
					 "/data/vendor/wifi/%s", file_name);
			}
		}
		cnss_plat_save_file(full_path_filename, p_qdss_trace_data,
				    total_size, true, gdata->qdss_max_file_len);
	} else {
		wsvc_printf_err("%s: QDSS trace file corrupted: remaining %u, "
				"end_valid %u, end %u",	__func__,
				remaining, resp.end_valid, resp.end);
		rc = -1;
		goto fail;
	}

fail:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_DATA_REQ_V01, rc,
			      resp_err_msg);
	free(p_qdss_trace_data);
end:
	return rc;
}

static int wlfw_send_qdss_trace_mode_req(wlfw_qdss_trace_mode_enum_v01 mode,
					 unsigned long long option,
					 struct wlfw_client_data *gdata)
{
	int rc = QMI_NO_ERR;
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;
	wlfw_qdss_trace_mode_req_msg_v01 req;
	wlfw_qdss_trace_mode_resp_msg_v01 resp;
#ifdef ANDROID
	char hw_trc_disable_override[CNSS_ANDROID_PROPERTY_MAX + 1],
	     default_value[32];
	int tmp;
#endif

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.mode_valid = 1;
	req.mode = mode;
	req.option_valid = 1;
	req.option = option;

#ifdef ANDROID
	snprintf(default_value, 32, "%d", QMI_PARAM_INVALID_V01);
	property_get("persist.vendor.cnss-daemon.hw_trc_disable_override",
		     hw_trc_disable_override, default_value);
	hw_trc_disable_override[CNSS_ANDROID_PROPERTY_MAX] = '\0';
	tmp = atoi(hw_trc_disable_override);

	req.hw_trc_disable_override_valid = 1;
	req.hw_trc_disable_override =
		(tmp > QMI_PARAM_DISABLE_V01 ? QMI_PARAM_DISABLE_V01 :
		 (tmp < 0 ? QMI_PARAM_INVALID_V01 : tmp));
#else
	req.hw_trc_disable_override_valid = 0;
	req.hw_trc_disable_override = QMI_PARAM_INVALID_V01;
#endif
	wsvc_printf_dbg("%s: mode %u, option %llu, hw_trc_disable_override: %u",
			__func__, mode, option, req.hw_trc_disable_override);

	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_MODE_REQ_V01, 0, 0);
	rc = qmi_client_send_msg_sync(gdata->clnt_handler,
				      QMI_WLFW_QDSS_TRACE_MODE_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);
	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("Failed to send QDSS trace mode req: rc %d, result %d, error %d",
				rc,
				resp.resp.result,
				resp.resp.error);
		if (resp.resp.result)
			rc = -resp.resp.result;
		resp_err_msg = resp.resp.error;
	}

	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_MODE_REQ_V01, rc,
			      resp_err_msg);
	return rc;
}

int wlfw_qdss_trace_start(uint32_t instance_id)
{
	struct wlfw_client_data *gdata = get_gdata_by_instance_id(instance_id);

	if (!gdata)
		return -1;

	return wlfw_send_qdss_trace_mode_req(QMI_WLFW_QDSS_TRACE_ON_V01, 0,
					     gdata);
}

int wlfw_qdss_trace_stop(unsigned long long option, uint32_t instance_id)
{
	struct wlfw_client_data *gdata = get_gdata_by_instance_id(instance_id);
	int rc;

	if (!gdata)
		return -1;

	rc = wlfw_send_qdss_trace_mode_req(QMI_WLFW_QDSS_TRACE_OFF_V01,
					   option, gdata);

	if (rc) {
		wsvc_printf_err("Failed to Stop QDSS Tracing");
		return rc;
	}

	gdata->state &= ~CNSS_QDSS_STARTED;
	return rc;
}

void wlfw_set_qdss_max_file_len(uint32_t instance_id, uint32_t value)
{
	struct wlfw_client_data *gdata = get_gdata_by_instance_id(instance_id);

	if (!gdata)
		return;

	/* Value here is in Bytes, it is assumed the caller will take care of
	 * the conversion to Bytes
	 */
	gdata->qdss_max_file_len = value;
}

#ifdef IPQ
#define MAX_BOARD_NAME 20
#define __MAXLEN(x) #x
#define MAXLEN(x) __MAXLEN(x)
static int wlfw_get_fw_qdss_config_file_path(struct wlfw_client_data *gdata,
					     char *full_file_path,
					     uint32_t full_file_path_len)
{
	FILE *board_name_file = NULL;
	char board_name[MAX_BOARD_NAME+1] = {'\0'};
	char board_type[MAX_BOARD_NAME+1] = {'\0'};
	char temp_full_path[CNSS_MAX_FILE_PATH] = {};

	/* First check if custom QDSS file is present in /data/vendor/wifi/ */
	if (gdata->instance_id == PINE_1_ID ||
	    gdata->instance_id == PINE_2_ID) {
		/* File is of the format qdss_trace_config_qcn9000_pci0.bin */
		snprintf(temp_full_path, sizeof(temp_full_path),
			 "%s%s_qcn9000_pci%d%s",
			 DEFAULT_QDSS_CONFIG_PATH,
			 QDSS_TRACE_CONFIG_FILE_PREFIX,
			 (gdata->instance_id - PINE_1_ID),
			 QDSS_TRACE_CONFIG_FILE_SUFFIX);
	} else if (gdata->instance_id == SPRUCE_1_ID ||
		   gdata->instance_id == SPRUCE_2_ID) {
		/* File is of the format qdss_trace_config_qcn6122_0.bin */
		snprintf(temp_full_path, sizeof(temp_full_path),
			 "%s%s_qcn6122_%d%s",
			 DEFAULT_QDSS_CONFIG_PATH,
			 QDSS_TRACE_CONFIG_FILE_PREFIX,
			 (gdata->instance_id - SPRUCE_1_ID),
			 QDSS_TRACE_CONFIG_FILE_SUFFIX);
	} else {
		snprintf(temp_full_path, sizeof(temp_full_path),
			 "%s%s", DEFAULT_QDSS_CONFIG_PATH,
			 QDSS_TRACE_CONFIG_FILE);
	}

	if (access(temp_full_path, F_OK) == 0) {
		strlcpy(full_file_path, temp_full_path, full_file_path_len);
		wsvc_printf_info("%s: Using custom QDSS config file %s",
				 __func__, full_file_path);
		return 0;
	}

	/* If custom file is not present, check for file from /lib/firmware/ */
	memset(temp_full_path, 0, sizeof(temp_full_path));
	board_name_file = fopen("/tmp/sysinfo/board_name", "r");
	if (!board_name_file) {
		wsvc_printf_err("%s Unable to get board_name", __func__);
		return -1;
	}

	fscanf(board_name_file, "%" MAXLEN(MAX_BOARD_NAME) "s", board_name);
	fclose(board_name_file);

	if (gdata->instance_id == PINE_1_ID ||
	    gdata->instance_id == PINE_2_ID) {
		snprintf(board_type, sizeof(board_type), "qcn9000");
	} else if (gdata->instance_id == SPRUCE_1_ID ||
		   gdata->instance_id == SPRUCE_2_ID) {
		snprintf(board_type, sizeof(board_type), "qcn6122");
	} else if ((strstr(board_name, "hk")) ||
		   (strstr(board_name, "oak")) ||
		   (strstr(board_name, "ac"))) {
		snprintf(board_type, sizeof(board_type), "IPQ8074");
	} else if (strstr(board_name, "cp")) {
		snprintf(board_type, sizeof(board_type), "IPQ6018");
	} else if (strstr(board_name, "mp")) {
		snprintf(board_type, sizeof(board_type), "IPQ5018");
	} else {
		wsvc_printf_err("%s Invalid board_name %s",
				__func__, board_name);
		return -1;
	}

	snprintf(temp_full_path, sizeof(temp_full_path),
		 "%s%s%s%s", "/lib/firmware/",
		 board_type, "/", QDSS_TRACE_CONFIG_FILE);

	if (access(temp_full_path, F_OK) == -1) {
		wsvc_printf_err("%s: No such QDSS Config file %s",
				__func__, temp_full_path);
		return -1;
	}

	strlcpy(full_file_path, temp_full_path, full_file_path_len);
	return 0;
}

static void wlfw_set_default_qdss_file_len(struct wlfw_client_data *gdata)
{
	wlfw_set_qdss_max_file_len(gdata->instance_id, WLFW_LOW_MEM_FILE_LEN);
}
#else
static int wlfw_get_fw_qdss_config_file_path(struct wlfw_client_data *gdata,
					     char *full_file_path,
					     uint32_t full_file_path_len)
{
	UNUSED(gdata);

	if (access(QDSS_TRACE_CONFIG_FILE_NEW, F_OK) == 0)
		snprintf(full_file_path, full_file_path_len,
			 "%s", QDSS_TRACE_CONFIG_FILE_NEW);
	else
		snprintf(full_file_path, full_file_path_len,
			 "%s%s", DEFAULT_QDSS_CONFIG_PATH,
			 QDSS_TRACE_CONFIG_FILE);

	return 0;
}

static void wlfw_set_default_qdss_file_len(struct wlfw_client_data *gdata)
{
	wlfw_set_qdss_max_file_len(gdata->instance_id, CNSS_MAX_FILE_LEN);
}
#endif

int wlfw_send_qdss_trace_config_download_req(uint32_t instance_id)
{
	struct wlfw_client_data *gdata = get_gdata_by_instance_id(instance_id);
	int rc = FALSE;
	wlfw_qdss_trace_config_download_req_msg_v01 req;
	wlfw_qdss_trace_config_download_resp_msg_v01 resp;
	FILE *file = NULL;
	unsigned char *buffer, *temp;
	unsigned int file_len, remaining;
	char full_file_path[CNSS_MAX_FILE_PATH] = {};
	int resp_err_msg = QMI_RESULT_SUCCESS_V01;

	if (!gdata)
		return -1;

	wsvc_printf_dbg("%s", __func__);

	rc = wlfw_get_fw_qdss_config_file_path(gdata, full_file_path,
					       sizeof(full_file_path));
	if (rc) {
		wsvc_printf_err("%s: Failed to get QDSS config file", __func__);
		goto end;
	}

	wsvc_printf_dbg("%s Reading QDSS Config file %s",
			__func__, full_file_path);

	file = fopen(full_file_path, "rb");
	if (!file) {
		wsvc_printf_err("%s: Failed to find QDSS trace config file %s",
				__func__, full_file_path);
		rc = -1;
		goto end;
	}

	fseek(file, 0, SEEK_END);
	file_len = ftell(file);
	fseek(file, 0, SEEK_SET);

	buffer = (unsigned char *)malloc(file_len);
	if (buffer == NULL) {
		wsvc_printf_err("%s: Fail to alloc memory for QDSS config file",
					 __func__);
		rc = -1;
		goto memory_alloc_fail;
	}
	if (fread(buffer, 1, file_len, file) != file_len) {
		wsvc_printf_err("%s: Fail to read QDSS config file", __func__);
		rc = -1;
		goto read_fail;
	}
	fclose(file);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	wsvc_printf_dbg("%s: size %u", __func__, file_len);

	temp = buffer;
	remaining = file_len;
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_CONFIG_DOWNLOAD_REQ_V01,
			      0, 0);
	while (remaining) {
		req.total_size_valid = 1;
		req.total_size = file_len;
		req.seg_id_valid = 1;
		req.data_valid = 1;
		req.end_valid = 1;
		if (remaining > QMI_WLFW_MAX_DATA_SIZE_V01) {
			req.data_len = QMI_WLFW_MAX_DATA_SIZE_V01;
		} else {
			req.data_len = remaining;
			req.end = 1;
		}
		memcpy(req.data, temp, req.data_len);

		rc = qmi_client_send_msg_sync(gdata->clnt_handler,
			QMI_WLFW_QDSS_TRACE_CONFIG_DOWNLOAD_REQ_V01,
			&req, sizeof(req), &resp, sizeof(resp),
			WLFW_TIMEOUT_MS);
		if ((rc != QMI_NO_ERR) ||
		    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
			wsvc_printf_err("%s: rc %d, result %d, error %d",
					__func__,
					rc,
					resp.resp.result,
					resp.resp.error);
			if (resp.resp.result)
				rc = -resp.resp.result;
			resp_err_msg = resp.resp.error;
			goto out;
		}

		remaining -= req.data_len;
		temp += req.data_len;
		req.seg_id++;
	}

out:
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_CONFIG_DOWNLOAD_REQ_V01, rc,
			      resp_err_msg);
	free(buffer);
	buffer = NULL;
	return rc;
read_fail:
	free(buffer);
	buffer = NULL;
memory_alloc_fail:
	fclose(file);
end:
	return rc;
}

void wlfw_qdss_trace_config_download_and_start(uint32_t instance_id)
{
	struct wlfw_client_data *gdata = get_gdata_by_instance_id(instance_id);
	int ret, timeout = 0;
	struct timespec ts;

	if (!gdata)
		return;

	if (CNSS_IS_QDSS_STARTED(gdata->state)) {
		wsvc_printf_err("QDSS already started, please stop before starting again");
		return;
	}

	/* FW will initiate new QDSS Mem Req sequence, unset the QDSS_MEM_READY
	 * flag here
	 */
	gdata->state &= ~CNSS_QDSS_MEM_READY;

	ret = wlfw_send_qdss_trace_config_download_req(gdata->instance_id);
	if (ret) {
		wsvc_printf_err("Failed to send QDSS Trace Load Config");
		return;
	}

	/* Wait for FW to complete QDSS Mem Req sequence with platform driver
	 * and send QDSS Mem Ready Indication
	 */
	while (!CNSS_IS_QDSS_MEM_READY(gdata->state)) {
		if (timeout > WLFW_QDSS_MEM_READY_TIMEOUT) {
			daemon_qmihist_record(gdata->instance_id,
					      QMI_WLFW_QDSS_MEM_READY_IND_V01,
					      QMI_TIMEOUT_ERR, QMI_TIMEOUT_ERR);
			wsvc_printf_err("Timed out waiting for QDSS Mem Ready");
			return;
		}
		wsvc_printf_dbg("Wait for QDSS memory ready indication");
		pthread_mutex_lock(&gdata->mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		timeout++;
		pthread_cond_timedwait(&gdata->cond_rsp, &gdata->mutex, &ts);
		pthread_mutex_unlock(&gdata->mutex);
	}

	ret = wlfw_qdss_trace_start(gdata->instance_id);
	if (ret) {
		wsvc_printf_err("Failed to start QDSS Tracing");
		return;
	}

	gdata->state |= CNSS_QDSS_STARTED;
}

static
void wlfw_handle_initiate_cal_download_ind(void *ind_buf,
					   unsigned int ind_buf_len,
					   struct wlfw_client_data *gdata)
{
	qmi_client_error_type rc = QMI_NO_ERR;
	wlfw_initiate_cal_download_ind_msg_v01 decoded_ind_buf;
	struct cnss_evt *evt;

	wsvc_printf_dbg("%s", __func__);

	memset(&decoded_ind_buf, 0, sizeof(decoded_ind_buf));
	rc = qmi_client_message_decode(gdata->clnt_handler,
				       QMI_IDL_INDICATION,
				       QMI_WLFW_INITIATE_CAL_DOWNLOAD_IND_V01,
				       ind_buf,
				       ind_buf_len,
				       &decoded_ind_buf,
				       sizeof(decoded_ind_buf));
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_INITIATE_CAL_DOWNLOAD_IND_V01, rc, 0);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("%s: fail to decode msg", __func__);
		return;
	}

	evt = cnss_evt_alloc(QMI_WLFW_INITIATE_CAL_DOWNLOAD_IND_V01,
			     &decoded_ind_buf, sizeof(decoded_ind_buf));
	if (!evt) {
		wsvc_printf_err("%s: failed to alloc memory for evt",
				__func__);
		return;
	}
	cnss_evt_enqueue(&gdata->evt_q, evt);

	pthread_mutex_lock(&(gdata->mutex));
	gdata->cond_signaled = true;
	pthread_cond_signal(&(gdata->cond));
	pthread_mutex_unlock(&(gdata->mutex));

	return;
}

static
void wlfw_handle_initiate_cal_update_ind(void *ind_buf,
					 unsigned int ind_buf_len,
					 struct wlfw_client_data *gdata)
{
	qmi_client_error_type rc;
	wlfw_initiate_cal_update_ind_msg_v01 decoded_ind_buf;
	struct cnss_evt *evt;

	wsvc_printf_dbg("%s", __func__);

	memset(&decoded_ind_buf, 0, sizeof(decoded_ind_buf));
	rc = qmi_client_message_decode(gdata->clnt_handler,
				       QMI_IDL_INDICATION,
				       QMI_WLFW_INITIATE_CAL_UPDATE_IND_V01,
				       ind_buf,
				       ind_buf_len,
				       &decoded_ind_buf,
				       sizeof(decoded_ind_buf));
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_INITIATE_CAL_UPDATE_IND_V01, rc, 0);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("%s: fail to decode msg", __func__);
		return;
	}

	evt = cnss_evt_alloc(QMI_WLFW_INITIATE_CAL_UPDATE_IND_V01,
			     &decoded_ind_buf, sizeof(decoded_ind_buf));
	if (!evt) {
		wsvc_printf_err("%s: failed to alloc memory for evt",
				__func__);
		return;
	}
	cnss_evt_enqueue(&gdata->evt_q, evt);

	pthread_mutex_lock(&(gdata->mutex));
	gdata->cond_signaled = true;
	pthread_cond_signal(&(gdata->cond));
	pthread_mutex_unlock(&(gdata->mutex));

	return;
}

static void wlfw_handle_qdss_trace_save_ind(void *ind_buf,
					    unsigned int ind_buf_len,
					    struct wlfw_client_data *gdata)
{
	qmi_client_error_type rc;
	wlfw_qdss_trace_save_ind_msg_v01 decoded_ind_buf;
	struct cnss_evt *evt;

	wsvc_printf_dbg("%s", __func__);

	memset(&decoded_ind_buf, 0, sizeof(decoded_ind_buf));
	rc = qmi_client_message_decode(gdata->clnt_handler,
				       QMI_IDL_INDICATION,
				       QMI_WLFW_QDSS_TRACE_SAVE_IND_V01,
				       ind_buf,
				       ind_buf_len,
				       &decoded_ind_buf,
				       sizeof(decoded_ind_buf));
	daemon_qmihist_record(gdata->instance_id,
			      QMI_WLFW_QDSS_TRACE_SAVE_IND_V01, rc, 0);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("%s: fail to decode msg", __func__);
		return;
	}

	evt = cnss_evt_alloc(QMI_WLFW_QDSS_TRACE_SAVE_IND_V01,
			     &decoded_ind_buf, sizeof(decoded_ind_buf));
	if (!evt) {
		wsvc_printf_err("%s: failed to alloc memory for evt",
				__func__);
		return;
	}
	cnss_evt_enqueue(&gdata->evt_q, evt);

	pthread_mutex_lock(&(gdata->mutex));
	gdata->cond_signaled = true;
	pthread_cond_signal(&(gdata->cond));
	pthread_mutex_unlock(&(gdata->mutex));
}

static void wlfw_qmi_ind_cb(qmi_client_type user_handle,
			    unsigned int msg_id,
			    void *ind_buf,
			    unsigned int ind_buf_len,
			    void *ind_cb_data)
{
	struct wlfw_client_data *gdata = (struct wlfw_client_data *)ind_cb_data;
	if ((ind_buf_len > 0) && (NULL == user_handle || NULL == ind_buf)) {
		wsvc_printf_err("%s: Invalid parameter(s) user_handle %pK:"
			"ind_buf %pK: ind_buf_len %d", __func__, user_handle,
			ind_buf, ind_buf_len);
		return;
	}

	wsvc_printf_dbg("%s: Receive Ind : 0x%x", __func__, msg_id);

	switch (msg_id) {
	case QMI_WLFW_FW_READY_IND_V01:
		/* turn off Adrastea */
		daemon_qmihist_record(gdata->instance_id,
				      QMI_WLFW_FW_READY_IND_V01, 0, 0);
		break;
	case QMI_WLFW_INITIATE_CAL_DOWNLOAD_IND_V01:
		wlfw_handle_initiate_cal_download_ind(ind_buf,
					     ind_buf_len, gdata);
		break;
	case QMI_WLFW_INITIATE_CAL_UPDATE_IND_V01:
		wlfw_handle_initiate_cal_update_ind(ind_buf,
					   ind_buf_len, gdata);
		break;
	case QMI_WLFW_MSA_READY_IND_V01:
		wsvc_printf_dbg("%s: Received MSA Ready Ind", __func__);
		pthread_mutex_lock(&gdata->mutex);
		gdata->state |= CNSS_MSA_READY;
		pthread_cond_signal(&gdata->cond_rsp);
		pthread_mutex_unlock(&gdata->mutex);
		break;
	case QMI_WLFW_FW_MEM_READY_IND_V01:
		wsvc_printf_dbg("%s: Received FW memory ready indication",
				__func__);
		daemon_qmihist_record(gdata->instance_id,
				      QMI_WLFW_FW_MEM_READY_IND_V01, 0, 0);
		pthread_mutex_lock(&gdata->mutex);
		gdata->state |= CNSS_FW_MEM_READY;
		pthread_cond_signal(&gdata->cond_rsp);
		pthread_mutex_unlock(&gdata->mutex);
		break;
	case QMI_WLFW_QDSS_TRACE_SAVE_IND_V01:
		wlfw_handle_qdss_trace_save_ind(ind_buf,
						ind_buf_len, gdata);
		break;
	case QMI_WLFW_QDSS_MEM_READY_IND_V01:
		wsvc_printf_dbg("%s: Received QDSS memory ready indication",
				__func__);
		daemon_qmihist_record(gdata->instance_id,
				      QMI_WLFW_QDSS_MEM_READY_IND_V01, 0, 0);
		pthread_mutex_lock(&gdata->mutex);
		gdata->state |= CNSS_QDSS_MEM_READY;
		pthread_cond_signal(&gdata->cond_rsp);
		pthread_mutex_unlock(&gdata->mutex);
		break;
	default:
		wsvc_printf_err("%s: Unsupported Ind %u",
				__func__, msg_id);
		break;
	}
}

static void wlfw_qmi_err_cb(qmi_client_type user_handle,
			    qmi_client_error_type error,
			    void *err_cb_data)
{
	int rc;
	struct wlfw_client_data *gdata = (struct wlfw_client_data *)err_cb_data;

	if (user_handle == NULL) {
		wsvc_printf_err("%s: Invalid user_handle", __func__);
		return;
	}
	(void)err_cb_data;

	wsvc_printf_info_high("%s: Server disconnect, err %d client %pK",
			 __func__, error, (void *)user_handle);

	gdata->state = 0;

	rc = wlfw_stop(SVC_DISCONNECTED, gdata->index);
	if (rc != 0) {
		wsvc_printf_err("%s: Fail to stop wlfw client", __func__);
		return;
	}
	rc = wlfw_start(SVC_RECONNECT, gdata->index);
	if (rc != 0) {
		wsvc_printf_err("%s: Fail to re-start wlfw client", __func__);
		return;
	}
}

void wlfw_handle_ind_data(struct cnss_evt *evt, struct wlfw_client_data *gdata)
{
	wsvc_printf_dbg("%s", __func__);

	if (!evt || !evt->data) {
		wsvc_printf_err("%s: Invalid data", __func__);
		return;
	}

	if ((CNSS_IS_WLFW_QMI_CONNECTED(gdata->state)) == 0) {
		wsvc_printf_err("%s: service disconnected, "
				"ignor this ind_data", __func__);
		return;
	}

	wsvc_printf_dbg("%s: msg_id 0x%d ",__func__, evt->msg_id);
	switch (evt->msg_id) {
	case QMI_WLFW_INITIATE_CAL_DOWNLOAD_IND_V01:
		wlfw_send_cal_download_req(evt->data, gdata);
		break;
	case QMI_WLFW_INITIATE_CAL_UPDATE_IND_V01:
		wlfw_send_cal_update_req(evt->data, gdata);
		break;
	case QMI_WLFW_QDSS_TRACE_SAVE_IND_V01:
		wlfw_send_qdss_trace_data_req(evt->data, gdata);
		break;
	default:
		wsvc_printf_dbg("%s: Invalid msg_id 0x%x",
				__func__, evt->msg_id);
		break;
	}
}

void wlfw_build_cal_table(struct wlfw_client_data *gdata)
{
	char filename[CNSS_MAX_FILE_PATH];
	int len_read;
	unsigned char *pcal;
	int id;

	pthread_mutex_lock(&(gdata->cal_mutex));
	for (id = 0; id < QMI_WLFW_MAX_NUM_CAL_V01; id++) {
		if (gdata->instance_id == PINE_1_ID ||
		    gdata->instance_id == PINE_2_ID)
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d_qcn9000_pci%d.bin", id,
				 (gdata->instance_id - PINE_1_ID));
		else if (gdata->instance_id == SPRUCE_1_ID ||
			 gdata->instance_id == SPRUCE_2_ID)
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d_qcn6122_%d.bin", id,
				 (gdata->instance_id - SPRUCE_1_ID));
		else
			snprintf(filename, sizeof(filename),
				 CAL_FILE"%02d.bin", id);

		if ((len_read = cnss_plat_read_file(filename, &pcal)) <= 0) {
			wsvc_printf_info("%s: not read %s", __func__, filename);
			gdata->cal_data_array[id].cal_id = 0;
			gdata->cal_data_array[id].total_size = 0;
			if (gdata->cal_data_array[id].data) {
				free(gdata->cal_data_array[id].data);
				gdata->cal_data_array[id].data = NULL;
			}
			continue;
		}
		gdata->cal_data_array[id].cal_id = id;
		gdata->cal_data_array[id].total_size = len_read;
		/* Free old cal data if any for the ID */
		if (gdata->cal_data_array[id].data)
			free(gdata->cal_data_array[id].data);
		gdata->cal_data_array[id].data = pcal;
	}
	pthread_mutex_unlock(&(gdata->cal_mutex));
	return;
}

static int wlfw_hawkeye_init(struct wlfw_client_data *gdata)
{
	int rc;
	uint64_t fw_status = 0;
	struct timespec ts;
	gdata->dms_running = 0;

	wlfw_build_cal_table(gdata);

	rc = wlfw_send_ind_register_req(&fw_status, gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send indication register request!");
		return rc;
	}

	if (fw_status & QMI_WLFW_ALREADY_REGISTERED_V01) {
		wsvc_printf_info("Already registered to FW, FW status: 0x%" PRIx64,
				 fw_status);

		if (fw_status & QMI_WLFW_FW_MEM_READY_V01) {
			wsvc_printf_dbg("FW memory is ready");
			gdata->state |= CNSS_FW_MEM_READY;
		}

		if (fw_status & QMI_WLFW_FW_READY_V01) {
			wsvc_printf_info("FW is already ready, skip!");
			goto out;
		}
	}

	pthread_mutex_lock(&gdata->mutex);
	while (!CNSS_IS_FW_MEM_READY(gdata->state)) {
		wsvc_printf_dbg("Wait for FW memory ready indication");
		memset(&ts, 0, sizeof(ts));
		if (clock_gettime(CLOCK_REALTIME, &ts)) {
			pthread_mutex_unlock(&gdata->mutex);
			wsvc_printf_err("%s: Failed to get time, err: %d",
				       __func__, errno);
			rc = -errno;
			return rc;
		}
		ts.tv_sec += 1;
		pthread_cond_timedwait(&gdata->cond_rsp, &gdata->mutex, &ts);
	}
	pthread_mutex_unlock(&gdata->mutex);

	wlfw_send_cap_req(gdata);
	wlfw_send_cal_report_req(gdata);

out:
	return QMI_NO_ERR;
}

static int wlfw_moselle_init(struct wlfw_client_data *gdata)
{
	int rc;
	uint64_t fw_status = 0;
	struct timespec ts;

	wlfw_build_cal_table(gdata);

	rc = wlfw_send_ind_register_req(&fw_status, gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send indication register request!");
		return rc;
	}

	wsvc_printf_info("FW status: 0x%" PRIx64, fw_status);

	if (fw_status & QMI_WLFW_FW_MEM_READY_V01) {
		wsvc_printf_dbg("FW memory is ready");
		gdata->state |= CNSS_FW_MEM_READY;
	}

	if (fw_status & QMI_WLFW_FW_READY_V01) {
		wsvc_printf_info("FW is already ready, skip!");
		goto out;
	}

	pthread_mutex_lock(&gdata->mutex);
	while (!CNSS_IS_FW_MEM_READY(gdata->state)) {
		wsvc_printf_dbg("Wait for FW memory ready indication");
		memset(&ts, 0, sizeof(ts));
		if (clock_gettime(CLOCK_REALTIME, &ts)) {
			pthread_mutex_unlock(&gdata->mutex);
			wsvc_printf_err("%s: Failed to get time, err: %d",
				       __func__, errno);
			rc = -errno;
			return rc;
		}
		ts.tv_sec += 1;
		pthread_cond_timedwait(&gdata->cond_rsp, &gdata->mutex, &ts);
	}
	pthread_mutex_unlock(&gdata->mutex);

out:
#ifdef CONFIG_READ_NV_MAC_ADDR
	wsvc_printf_dbg("pthread_cond_signal dms_cond");
	pthread_mutex_lock(&(gdata->dms_mutex));
	gdata->state |= CNSS_BDF_DOWNLOAD_DONE;
	pthread_cond_signal(&(gdata->dms_cond));
	pthread_mutex_unlock(&(gdata->dms_mutex));
#endif
	return QMI_NO_ERR;
}

static int wlfw_napier_init(struct wlfw_client_data *gdata)
{
	int rc;
	uint64_t fw_status = 0;
	struct timespec ts;

	pm_deinit(gdata, MDM_TYPE_INTERNAL);
	pm_deinit(gdata, MDM_TYPE_EXTERNAL);

	wlfw_build_cal_table(gdata);

	rc = wlfw_send_ind_register_req(&fw_status, gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send indication register request!");
		return rc;
	}

	wsvc_printf_info("FW status: 0x%" PRIx64, fw_status);

	if (fw_status & QMI_WLFW_FW_MEM_READY_V01) {
		wsvc_printf_dbg("FW memory is ready");
		gdata->state |= CNSS_FW_MEM_READY;
	}

	if (fw_status & QMI_WLFW_FW_READY_V01) {
		wsvc_printf_info("FW is already ready, skip!");
		goto out;
	}

	pthread_mutex_lock(&gdata->mutex);
	while (!CNSS_IS_FW_MEM_READY(gdata->state)) {
		wsvc_printf_dbg("Wait for FW memory ready indication");
		memset(&ts, 0, sizeof(ts));
		if (clock_gettime(CLOCK_REALTIME, &ts)) {
			pthread_mutex_unlock(&gdata->mutex);
			wsvc_printf_err("%s: Failed to get time, err: %d",
				       __func__, errno);
			rc = -errno;
			return rc;
		}
		ts.tv_sec += 1;
		pthread_cond_timedwait(&gdata->cond_rsp, &gdata->mutex, &ts);
	}
	pthread_mutex_unlock(&gdata->mutex);

	rc = wlfw_send_cap_req(gdata);
	if (rc)
		return rc;

	wlfw_send_cal_report_req(gdata);

out:
#ifdef CONFIG_READ_NV_MAC_ADDR
	wsvc_printf_dbg("pthread_cond_signal dms_cond");
	pthread_mutex_lock(&(gdata->dms_mutex));
	gdata->state |= CNSS_BDF_DOWNLOAD_DONE;
	pthread_cond_signal(&(gdata->dms_cond));
	pthread_mutex_unlock(&(gdata->dms_mutex));
#endif
	return QMI_NO_ERR;
}

static int wlfw_adrastea_init(struct wlfw_client_data *gdata)
{
	int rc;
	int16_t bdf_retry = 0;
	int16_t regdb_retry = 0;
	uint64_t fw_status = 0;
	struct timespec ts;

	wlfw_build_cal_table(gdata);

	rc = wlfw_send_ind_register_req(&fw_status, gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send indication register request!");
		return rc;
	}

	if (fw_status & QMI_WLFW_ALREADY_REGISTERED_V01) {
		if (!(fw_status & QMI_WLFW_FW_READY_V01)) {
			wsvc_printf_err("FW in bad state 0x%" PRIx64,
							fw_status);
			goto skip_mac_addr;
		}
		goto skip_cal_report;
	}

	if (fw_status & QMI_WLFW_MSA_READY_V01) {
		wsvc_printf_dbg("MSA is ready");
		gdata->state |= CNSS_MSA_READY;
	}

	pthread_mutex_lock(&gdata->mutex);
	while (!CNSS_IS_MSA_READY(gdata->state))
	{
		wsvc_printf_dbg("Wait for MSA ready Indication from FW");
		memset(&ts, 0, sizeof(ts));
		if (clock_gettime(CLOCK_REALTIME, &ts)) {
			pthread_mutex_unlock(&gdata->mutex);
			wsvc_printf_err("%s: Failed to get time, err: %d",
				       __func__, errno);
			rc = -errno;
			return rc;
		}
		ts.tv_sec += 1;
		pthread_cond_timedwait(&gdata->cond_rsp, &gdata->mutex, &ts);
	}
	pthread_mutex_unlock(&gdata->mutex);

	rc = wlfw_send_cap_req(gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send capability request");
		goto skip_mac_addr;
	}

	/* Do BDF REGDB retry */
	do {
		rc = wlfw_send_bdf_download_req(CNSS_BDF_REGDB, gdata);
	} while (regdb_retry++ < WLFW_MAX_BDF_RETRY && (FALSE == rc));

	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to Download the REGDB File");
	}

	/* Do BDF retry */
	do {
		rc = wlfw_send_bdf_download_req(CNSS_BDF_BIN, gdata);
	} while (bdf_retry++ < WLFW_MAX_BDF_RETRY && (FALSE == rc));

	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to Download the BDF File");
		gdata->state = 0;
		return rc;
	}

	rc = wlfw_send_cal_report_req(gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to send cal_report_request");
		goto skip_mac_addr;
	}

skip_cal_report:
	/* Intention here is to not intersect MAC address configuration and BDF
	 * download */
#ifdef CONFIG_READ_NV_MAC_ADDR
	wsvc_printf_dbg("pthread_cond_signal dms_cond");
	pthread_mutex_lock(&(gdata->dms_mutex));
	gdata->state |= CNSS_BDF_DOWNLOAD_DONE;
	pthread_cond_signal(&(gdata->dms_cond));
	pthread_mutex_unlock(&(gdata->dms_mutex));
#endif
skip_mac_addr:
	return rc;
}

void *wlfw_service_request(void *arg)
{
	int rc;
	qmi_client_type clnt;
	qmi_cci_os_signal_type os_params;
	qmi_service_info info;
	struct cnss_evt *evt = NULL;
	struct wlfw_client_data *gdata = (struct wlfw_client_data *)arg;

	wsvc_printf_info_high("%s: Start the pthread: %pK", __func__, arg);

	/* release any old handles for qmi client */
	if (gdata->clnt_handler) {
		qmi_client_release(gdata->clnt_handler);
		gdata->clnt_handler = NULL;
	}

	gdata->svc_obj = wlfw_get_service_object_v01();

	wsvc_printf_dbg("%s: Creating client instance for ID 0x%x",
			__func__, gdata->instance_id);
	rc = qmi_client_init_instance(gdata->svc_obj,
				      gdata->instance_id,
				      wlfw_qmi_ind_cb,
				      gdata,
				      &os_params,
				      0,
				      &clnt);

	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to init client");
		return NULL;
	}

	rc = qmi_client_register_error_cb(clnt,
					  wlfw_qmi_err_cb,
					  gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to register error cb");
		goto release_client;
	}

	gdata->clnt_handler = clnt;
	gdata->state |= CNSS_WLFW_QMI_CONNECTED;

	wsvc_printf_info("WLFW service connected");

	rc = qmi_client_get_service_instance(gdata->svc_obj,
					     gdata->instance_id,
					     &info);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to get service instance!");
		goto release_client;
	}

	rc = qmi_client_get_instance_id(&info, &gdata->instance_id);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to get instance ID!");
		goto release_client;
	}

	if ((gdata->instance_id == NAPIER_ID) ||
	    (gdata->instance_id == HASTINGS_ID) ||
	    (gdata->instance_id == PINE_1_ID) ||
	    (gdata->instance_id == PINE_2_ID))
		rc = wlfw_napier_init(gdata);
	else if (gdata->instance_id == ADRASTEA_ID)
		rc = wlfw_adrastea_init(gdata);
	else if ((gdata->instance_id == HAWKEYE_ID) ||
		  (gdata->instance_id == SPRUCE_1_ID) ||
		  (gdata->instance_id == SPRUCE_2_ID))
		rc = wlfw_hawkeye_init(gdata);
	else if (gdata->instance_id == MOSELLE_ID)
		rc = wlfw_moselle_init(gdata);

	if (rc != QMI_NO_ERR)
		goto unset_state;

	while (gdata->svc_running) {
		pthread_mutex_lock(&(gdata->mutex));
		while (!gdata->cond_signaled)
			pthread_cond_wait(&gdata->cond, &gdata->mutex);

		gdata->cond_signaled = false;
		pthread_mutex_unlock(&(gdata->mutex));

		if (!gdata->svc_running)
			break;

		evt = cnss_evt_dequeue(&gdata->evt_q);
		while (evt) {
			/* handle ind */
			wlfw_handle_ind_data(evt, gdata);
			if (evt->data)
				free(evt->data);
			free(evt);
			evt = cnss_evt_dequeue(&gdata->evt_q);
		}
	}

	wsvc_printf_info("%s: Pthread exiting", __func__);

	return NULL;

release_client:
	qmi_client_release(clnt);
unset_state:
	gdata->state &= ~CNSS_WLFW_QMI_CONNECTED;
	return NULL;
}

#ifdef CONFIG_READ_NV_MAC_ADDR
int dms_get_wlan_address(qmi_client_type clnt, struct wlfw_client_data *gdata)
{
	int rc;
	dms_get_mac_address_req_msg_v01 req;
	dms_get_mac_address_resp_msg_v01 resp;

	wsvc_printf_dbg("Sending DMS get mac address");

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.device = DMS_DEVICE_MAC_WLAN_V01;

	rc = qmi_client_send_msg_sync(clnt,
				      QMI_DMS_GET_MAC_ADDRESS_REQ_V01,
				      &req,
				      sizeof(req),
				      &resp,
				      sizeof(resp),
				      WLFW_TIMEOUT_MS);
	if ((rc != QMI_NO_ERR) ||
	    (resp.resp.result != QMI_RESULT_SUCCESS_V01)) {
		wsvc_printf_err("Send DMS get mac address failed: rc %d, result %d, error %d",
				rc,
				resp.resp.result,
				resp.resp.error);
		if (resp.resp.result)
			rc = -resp.resp.result;
		goto out;
	}

	wsvc_printf_dbg("Read MAC address: valid %u, len %u",
			resp.mac_address_valid,
			resp.mac_address_len);

	if (resp.mac_address_valid &&
	    resp.mac_address_len == QMI_WLFW_MAC_ADDR_SIZE_V01) {
		gdata->mac_addr.mac_addr_valid = 1;
		memcpy(gdata->mac_addr.mac_addr, resp.mac_address,
		       QMI_WLFW_MAC_ADDR_SIZE_V01);
		wsvc_printf_mac_addr(MSG_DEBUG, "Read MAC address",
				     gdata->mac_addr.mac_addr);
	} else {
		gdata->mac_addr.mac_addr_valid = 0;
		memset(gdata->mac_addr.mac_addr, 0,
		       sizeof(uint8_t) * QMI_WLFW_MAC_ADDR_SIZE_V01);
	}

out:
	return rc;
}
#else
int dms_get_wlan_address(qmi_client_type clnt, struct wlfw_client_data *gdata)
{
	UNUSED(clnt);
	UNUSED(gdata);
	return 0;
}
#endif

#ifdef CONFIG_READ_NV_MAC_ADDR
int check_modem_compatability(struct dev_info *mdm_detect_info)
{
	char args[MAX_PROPERTY_SIZE] = {0};
	int ret = 0;
	/* Get the hardware property */
	ret = property_get(MODEM_BASEBAND_PROPERTY, args, "");
	if (ret > MAX_PROPERTY_SIZE) {
		wsvc_printf_err("property [%s] has size [%d] that exceeds max [%d]",
				MODEM_BASEBAND_PROPERTY, ret,
				MAX_PROPERTY_SIZE);
		return 0;
	}
	wsvc_printf_info("ro.baseband : [%s]", args);

	/* This will check for the type of hardware, and if the
	   hardware type needs external modem, it will check if the
	   modem type is external*/
	if((!strncmp(MODEM_BASEBAND_VALUE_APQ, args, 3)) ||
	    (!strncmp(MODEM_BASEBAND_VALUE_SDA, args, 3)) ||
	    !strncmp(MODEM_BASEBAND_VALUE_QCS, args, 3)) {
		for (ret = 0; ret < mdm_detect_info->num_modems; ret++) {
			if (mdm_detect_info->mdm_list[ret].type ==
			    MDM_TYPE_EXTERNAL) {
				wsvc_printf_err("Hardware supports external modem");
				return 1;
			}
		}
		wsvc_printf_err("Hardware does not support external modem");
		return 0;
	}
	return 1;
}

void *dms_service_request(void *arg)
{
	int rc;
	qmi_idl_service_object_type svc_obj;
	qmi_client_type clnt;
	qmi_cci_os_signal_type os_params;
	struct dev_info mdm_detect_info;
	struct wlfw_client_data *gdata = (struct wlfw_client_data *)arg;

	wsvc_printf_dbg("%s: Start DMS pthread: %pK", __func__, arg);

	rc = get_system_info(&mdm_detect_info);
	if (rc > 0) {
		wsvc_printf_err("Failed to get system info, ret %d", rc);
		goto out;
	}

	if (mdm_detect_info.num_modems == 0) {
		wsvc_printf_err("No Modem support for this target"
		      " number of modems is %d", mdm_detect_info.num_modems);
		goto out;
	}

	if(!check_modem_compatability(&mdm_detect_info)) {
		wsvc_printf_err("Target does not have external modem");
		goto out;
	}

	svc_obj = dms_get_service_object_v01();

	do {
		rc = qmi_client_init_instance(svc_obj,
					      QMI_CLIENT_INSTANCE_ANY,
					      NULL,
					      NULL,
					      &os_params,
					      WLFW_TIMEOUT_DMS_MS,
					      &clnt);
		if (rc == QMI_NO_ERR) {
			break;
		} else if (rc != QMI_TIMEOUT_ERR) {
			wsvc_printf_err("Failed to init DMS client, ret %d",
					rc);
			goto out;
		}
	} while (gdata->dms_running);

	if (rc != QMI_NO_ERR) {
		wsvc_printf_info("Exit DMS pthread for instance_id %d ,ret %d\n",
				 gdata->instance_id, rc);
		goto out;
	}

	rc = dms_get_wlan_address(clnt, gdata);
	if (rc != QMI_NO_ERR) {
		wsvc_printf_err("Failed to get WLAN MAC address");
	} else if (gdata->mac_addr.mac_addr_valid) {
		int retry = 0;
		pthread_mutex_lock(&(gdata->dms_mutex));
		if (!CNSS_IS_BDF_DOWNLOAD_DONE(gdata->state) &&
		    gdata->svc_running) {
			wsvc_printf_dbg("Wait for CNSS_BDF_DOWNLOAD_DONE");
			pthread_cond_wait(&gdata->dms_cond, &gdata->dms_mutex);
		}
		pthread_mutex_unlock(&(gdata->dms_mutex));
		for (retry = 0; retry < 2 && gdata->svc_running; retry++)
		{
			rc = wlfw_send_mac_addr_req(gdata);
			if (rc == QMI_NO_ERR)
				break;
			usleep(500000);
		}
	}

	qmi_client_release(clnt);
out:
	gdata->dms_running = 0;
	return NULL;
}
#else
void *dms_service_request(void *arg, struct wlfw_client_data *gdata)
{
	UNUSED(arg);
	UNUSED(gdata);
	return NULL;
}
#endif

#ifdef CONFIG_READ_NV_MAC_ADDR
int pthread_initialize_dms(struct wlfw_client_data *gdata)
{
	int rc = 0;

	rc = pthread_cond_init(&(gdata->dms_cond), NULL);
	if (rc != 0) {
		wsvc_printf_err("Failed to init dms_cond, ret %d", rc);
		goto err_fail_dms_cond_rsp;
	}
	rc = pthread_mutex_init(&(gdata->dms_mutex), NULL);
	if (rc != 0) {
		wsvc_printf_err("Failed to init dms_mutex, ret %d", rc);
		goto err_fail_dms_mutex_create;
	}
	rc = pthread_create(&(gdata->thread_id_dms), NULL,
			    dms_service_request, NULL);
	if (rc != 0) {
		wsvc_printf_err("Failed to create DMS thread, ret %d", rc);
		goto err_fail_thread_create;
	}
	gdata->dms_running = 1;
	return rc;

err_fail_thread_create:
	rc = pthread_mutex_destroy(&(gdata->dms_mutex));
	if (rc != 0)
		wsvc_printf_err("Failed to destroy dms_mutex, ret %d", rc);

err_fail_dms_mutex_create:
	rc = pthread_cond_destroy(&(gdata->dms_cond));
	if (rc != 0)
		wsvc_printf_err("Failed to destroy dms_cond, ret %d", rc);
err_fail_dms_cond_rsp:
	return rc;
}
#else
int pthread_initialize_dms(struct wlfw_client_data *gdata)
{
	gdata->dms_running = 0;
	return 0;
}
#endif

#ifdef CAL_DATA_REMOVE
int remove_cal_data()
{
	int ret = 0;
	char filename[CNSS_MAX_FILE_PATH];
	int id;

	for (id = 0; id < QMI_WLFW_MAX_NUM_CAL_V01; id++) {

		snprintf(filename, sizeof(filename), CAL_FILE"%02d.bin", id);

		if (access(filename, F_OK) == 0) {
			ret = remove(filename);
			if (ret) {
				wsvc_printf_err("Not able to delete cal file %s",filename);
				break;
			}
		} else {
			wsvc_printf_info("%s cal file does not exists",filename);
		}
	}

	return ret;
}
#else
int remove_cal_data()
{
	return 0;
}
#endif

int wlfw_start(enum wlfw_svc_flag flag, uint8_t index)
{
	int rc = 0;
	struct wlfw_client_data *gdata = &client_data[index];

	wsvc_printf_info_high("%s: Starting", __func__);

	if (flag == SVC_START) {
		pm_init(gdata, MDM_TYPE_INTERNAL, NULL);
		pm_init(gdata, MDM_TYPE_EXTERNAL, "SDXPRAIRIE");
		if (remove_cal_data())
			 wsvc_printf_err("Unable to clear cal data");
	}

	rc = pthread_mutex_init(&(gdata->cal_mutex), NULL);
	if (0 != rc) {
		wsvc_printf_err("Failed to init cal_mutex, ret %d", rc);
		goto out;
	}

	rc = pthread_mutex_init(&(gdata->mutex), NULL);
	if (0 != rc) {
		wsvc_printf_err("Failed to init mutex, ret %d", rc);
		goto err_fail_cal_mutex;;
	}

#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
	rc = pthread_mutex_init(&(qmi_record_mutex), NULL);
	if (rc != 0) {
		wsvc_printf_err("Failed to init qmi_record_mutex, ret %d", rc);
		goto err_fail_mutex;
	}
#endif
	gdata->cond_signaled = false;
	rc = pthread_cond_init(&(gdata->cond), NULL);
	if (0 != rc) {
		wsvc_printf_err("Failed to init cond, ret %d", rc);
		goto err_fail_cond;
	}
	rc = pthread_cond_init(&(gdata->cond_rsp), NULL);
	if (0 != rc) {
		wsvc_printf_err("Failed to init cond_rsp, ret %d", rc);
		goto err_fail_cond_rsp;
	}

	rc = pthread_initialize_dms(gdata);
	if (rc != 0)
		goto err_fail_thread_create;

	gdata->instance_id = g_instance_id_array[index];
	gdata->index = index;
	wlfw_set_default_qdss_file_len(gdata);
	rc = pthread_create(&(gdata->thread_id), NULL,
			    wlfw_service_request, gdata);
	if (0 != rc) {
		wsvc_printf_err("Failed to create thread, ret %d", rc);
		gdata->instance_id = 0;
		goto err_fail_thread_create;
	}

#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
	daemon_debuglog_file = open(debug_file, O_RDWR);
	if (daemon_debuglog_file < 0) {
		wsvc_printf_err("%s:Unable to open daemon_qmilog_file",
				__func__);
	}
#endif

	gdata->svc_running = 1;
	wsvc_printf_dbg("%s: Start done: %d", __func__, rc);

	return rc;
err_fail_thread_create:
	rc = pthread_cond_destroy(&(gdata->cond_rsp));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy cond_rsp, ret %d", rc);
	}
err_fail_cond_rsp:
	rc = pthread_cond_destroy(&(gdata->cond));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy cond, ret %d", rc);
	}
err_fail_cond:
#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
	rc = pthread_mutex_destroy(&(qmi_record_mutex));
	if (rc != 0) {
		wsvc_printf_err("Failed to destroy qmi_record_mutex, ret %d", rc);
	}
err_fail_mutex:
#endif
	rc = pthread_mutex_destroy(&(gdata->mutex));
        if (0 != rc) {
		wsvc_printf_err("Failed to destroy mutex, ret %d", rc);
	}
err_fail_cal_mutex:
	rc = pthread_mutex_destroy(&(gdata->cal_mutex));
        if (0 != rc) {
		wsvc_printf_err("Failed to destroy cal_mutex, ret %d", rc);
	}
out:
	return rc;
}

#ifdef CONFIG_READ_NV_MAC_ADDR
void pthread_signal_and_join_dms(struct wlfw_client_data *gdata)
{
	int rc = 0;

	wsvc_printf_dbg("Signal DMS client");
	pthread_mutex_lock(&(gdata->dms_mutex));
	pthread_cond_signal(&(gdata->dms_cond));
	pthread_mutex_unlock(&(gdata->dms_mutex));
	wsvc_printf_dbg("Join DMS thread");
	pthread_join(gdata->thread_id_dms, NULL);
	if (rc != 0) {
		wsvc_printf_err("Failed to join dms mutex, ret %d", rc);
	}
}
void pthread_cleanup_dms(struct wlfw_client_data *gdata)
{
	int rc = 0;

	wsvc_printf_dbg("DMS thread cleanup");
	rc = pthread_cond_destroy(&(gdata->dms_cond));
	if (rc != 0) {
		wsvc_printf_err("Failed to destroy dms_cond, ret %d", rc);
	}
	rc = pthread_mutex_destroy(&(gdata->dms_mutex));
	if (rc != 0) {
		wsvc_printf_err("Failed to destroy dms_mutex, ret %d", rc);
	}
}
#else
void pthread_signal_and_join_dms(struct wlfw_client_data *gdata)
{
	UNUSED(gdata);
}

void pthread_cleanup_dms(struct wlfw_client_data *gdata)
{
	UNUSED(gdata);
}
#endif

int wlfw_stop(enum wlfw_svc_flag flag, uint8_t index)
{
	int rc = 0;
	struct wlfw_client_data *gdata = &client_data[index];

	if (!gdata->svc_running) {
		wsvc_printf_err("wlfw thread not started");
		return -EALREADY;
	}

	wsvc_printf_dbg("%s: Stopping: %d", __func__, flag);

	gdata->svc_running = 0;
	gdata->dms_running = 0;
	pthread_mutex_lock(&(gdata->mutex));
	pthread_cond_signal(&(gdata->cond_rsp));

	gdata->cond_signaled = true;
	pthread_cond_signal(&(gdata->cond));
	pthread_mutex_unlock(&(gdata->mutex));

	rc = pthread_join(gdata->thread_id, NULL);
	if (0 != rc) {
		wsvc_printf_err("Failed to join mutex, ret %d", rc);
	}
	pthread_signal_and_join_dms(gdata);

	wsvc_printf_info_high("DMS thread joined succesfully\n");

	if (gdata->clnt_handler && (flag == SVC_EXIT)) {
		qmi_client_release(gdata->clnt_handler);
		gdata->clnt_handler = NULL;
	}

	cnss_evt_free_queue(&gdata->evt_q);

	pthread_cleanup_dms(gdata);

	rc = pthread_cond_destroy(&(gdata->cond_rsp));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy cond_rsp, ret %d", rc);
	}
	rc = pthread_cond_destroy(&(gdata->cond));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy cond, ret %d", rc);
	}

#ifdef CONFIG_RECORD_DAEMON_QMI_LOG
	rc = pthread_mutex_destroy(&(qmi_record_mutex));
	if (rc != 0) {
		wsvc_printf_err("Failed to destroy qmi_record_mutex, ret %d", rc);
	}
	if (daemon_debuglog_file >= 0)
		close(daemon_debuglog_file);
#endif
	rc = pthread_mutex_destroy(&(gdata->mutex));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy mutex, ret %d", rc);
	}

	if (flag == SVC_EXIT) {
		/* Free and clear cached CAL data */
		free_cal_file(gdata);
		if (gdata->instance_id == ADRASTEA_ID) {
			pm_deinit(gdata, MDM_TYPE_INTERNAL);
			pm_deinit(gdata, MDM_TYPE_EXTERNAL);
		}
	}

	rc = pthread_mutex_destroy(&(gdata->cal_mutex));
	if (0 != rc) {
		wsvc_printf_err("Failed to destroy cal_mutex, ret %d", rc);
	}

	wsvc_printf_info_high("%s: Stop done: %d", __func__, rc);

	return rc;
}
