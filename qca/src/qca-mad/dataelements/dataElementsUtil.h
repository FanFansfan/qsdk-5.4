/*
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 */

#include "dataElements.h"
//Function to read integer INI values from config
int profileGetOptsInt(const char *Section, const char *Element, struct profileElement *DefaultTable);

//Function to read string INI values from config
const char *profileGetOpts(const char *Section, const char *Element, struct profileElement *DefaultTable);
